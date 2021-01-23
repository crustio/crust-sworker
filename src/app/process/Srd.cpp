#include "Srd.h"
#include "ECalls.h"
#include "Ctpl.h"
#include "HttpClient.h"

crust::Log *p_log = crust::Log::get_instance();

size_t g_srd_reserved_space = DEFAULT_SRD_RESERVED;
size_t g_running_srd_task = 0;
std::mutex g_running_srd_task_mutex;

extern sgx_enclave_id_t global_eid;

/**
 * @description: Get srd disks info according to configure
 * @param true_srd_capacity -> True assigned size
 * @return: A path to assigned size map
 */
json::JSON get_increase_srd_info()
{
    size_t true_srd_capacity = 0;
    // Get multi-disk info
    Config *p_config = Config::get_instance();
    json::JSON disk_info_json;
    long srd_reserved_space = get_reserved_space();
    // Create path
    if (create_directory(p_config->srd_path))
    {
        // Calculate free disk
        disk_info_json[WL_DISK_AVAILABLE] = get_avail_space_under_dir_g(p_config->srd_path);
        disk_info_json[WL_DISK_VOLUME] = get_total_space_under_dir_g(p_config->srd_path);
        if (disk_info_json[WL_DISK_AVAILABLE].ToInt() <= srd_reserved_space)
        {
            disk_info_json[WL_DISK_AVAILABLE_FOR_SRD] = 0;
        }
        else
        {
            disk_info_json[WL_DISK_AVAILABLE_FOR_SRD] = disk_info_json[WL_DISK_AVAILABLE].ToInt() - srd_reserved_space;
        }
        true_srd_capacity = disk_info_json[WL_DISK_AVAILABLE_FOR_SRD].ToInt();
    }
    else
    {
        true_srd_capacity = 0;
    }

    disk_info_json[WL_DISK_AVAILABLE_FOR_SRD] = true_srd_capacity;

    return disk_info_json;
}

/**
 * @description: Change SRD space
 * @param change -> SRD space number
 * @return: Srd change result
 */
crust_status_t srd_change(long change)
{
    Config *p_config = Config::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;

    if (change > 0)
    {
        json::JSON disk_info_json = get_increase_srd_info();
        size_t true_increase = std::min(disk_info_json[WL_DISK_AVAILABLE_FOR_SRD].ToInt(), change);
        // Add left change to next srd, if have
        if (change > (long)true_increase)
        {
            p_log->warn("No enough space for %ldG srd, can only do %ldG srd.\n", change, true_increase);
            crust_status = CRUST_SRD_NUMBER_EXCEED;
        }
        if (true_increase == 0)
        {
            //p_log->warn("No available space for srd!\n");
            return CRUST_SRD_NUMBER_EXCEED;
        }
        set_running_srd_task(true_increase);
        // Print disk info
        p_log->info("Available space is %ldG in '%s' folder, this turn will use %ldG space\n", 
                disk_info_json[WL_DISK_AVAILABLE_FOR_SRD].ToInt(),
                p_config->srd_path.c_str(),
                true_increase);
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);

        // ----- Do srd ----- //
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        ctpl::thread_pool pool(p_config->srd_thread_num);
        std::vector<std::shared_ptr<std::future<sgx_status_t>>> tasks_v;
        for (size_t i = 0; i < true_increase; i++)
        {
            sgx_enclave_id_t eid = global_eid;
            tasks_v.push_back(std::make_shared<std::future<sgx_status_t>>(pool.push([eid](int /*id*/){
                sgx_status_t sgx_status = SGX_SUCCESS;
                if (SGX_SUCCESS != Ecall_srd_increase(eid))
                {
                    // If failed, add current task to next turn
                    crust_status_t ret = CRUST_SUCCESS;
                    long real_change = 0;
                    Ecall_change_srd_task(global_eid, &ret, 1, &real_change);
                    sgx_status = SGX_ERROR_UNEXPECTED;
                }
                decrease_running_srd_task();
                return sgx_status;
            })));
        }
        // Wait for srd task
        size_t srd_success_num = 0;
        for (auto it : tasks_v)
        {
            try 
            {
                if (SGX_SUCCESS == it->get())
                {
                    srd_success_num++;
                }
            }
            catch (std::exception &e)
            {
                p_log->err("Catch exception:");
                std::cout << e.what() << std::endl;
            }
        }
        set_running_srd_task(0);

        if (srd_success_num < true_increase)
        {
            p_log->info("Srd task: %dG, success: %dG, left: %dG.\n", 
                    true_increase, srd_success_num, true_increase - srd_success_num);
        }
        else
        {
            p_log->info("Increase %dG srd files success.\n", true_increase);
        }
    }
    else if (change < 0)
    {
        size_t true_decrease = 0;
        set_running_srd_task(change);
        Ecall_srd_decrease(global_eid, &true_decrease, (size_t)-change);
        set_running_srd_task(0);
        p_log->info("Decrease %luG srd successfully.\n", true_decrease);
    }

    return crust_status;
}

/**
 * @description: Check if disk's available space is smaller than minimal reserved space,
 * if it is, delete srd space
 */
void srd_check_reserved(void)
{
    crust::DataBase *db = crust::DataBase::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    size_t check_interval = 10;

    while (true)
    {
        if (UPGRADE_STATUS_EXIT == EnclaveData::get_instance()->get_upgrade_status())
        {
            p_log->info("Stop srd check reserved for exit...\n");
            return;
        }

        std::string srd_info_str;
        long srd_reserved_space = get_reserved_space();
        // Lock srd_info
        crust_status = db->get(DB_SRD_INFO, srd_info_str);
        if (CRUST_SUCCESS != crust_status)
        {
            //p_log->debug("Srd info not found!Check srd reserved failed!\n");
            sleep(10);
            continue;
        }
        json::JSON srd_info_json = json::JSON::Load(srd_info_str);
        size_t avail_space = get_avail_space_under_dir_g(Config::get_instance()->srd_path);
        long del_space = 0;
        if ((long)avail_space < srd_reserved_space)
        {
            del_space = std::min((long)(srd_reserved_space - avail_space), (long)srd_info_json[WL_SRD_COMPLETE].ToInt());
        }

        // Do remove
        if (del_space > 0)
        {
            if (SGX_SUCCESS != Ecall_srd_remove_space(global_eid, (size_t)del_space))
            {
                p_log->err("Invoke srd metadata failed! Error code:%lx\n", sgx_status);
            }
        }
        
        // Wait
        for (size_t i = 0; i < check_interval; i++)
        {
            if (UPGRADE_STATUS_EXIT == EnclaveData::get_instance()->get_upgrade_status())
            {
                p_log->info("Stop srd check reserved for exit...\n");
                return;
            }
            sleep(1);
        }
    }
}

/**
 * @description: Get reserved space
 * @return: srd reserved space
 */
size_t get_reserved_space()
{
    return g_srd_reserved_space;
}

/**
 * @description: Set reserved space
 * @param reserved -> Reserved space
 */
void set_reserved_space(size_t reserved)
{
    g_srd_reserved_space = reserved;
}

/**
 * @description: Set running srd task number
 * @param srd_task -> Srd task number
 */
void set_running_srd_task(long srd_task)
{
    g_running_srd_task_mutex.lock();
    g_running_srd_task = srd_task;
    g_running_srd_task_mutex.unlock();
}

/**
 * @description: Get running srd task number
 * @return: Running task number
 */
long get_running_srd_task()
{
    long srd_task = 0;
    g_running_srd_task_mutex.lock();
    srd_task = g_running_srd_task;
    g_running_srd_task_mutex.unlock();

    return srd_task;
}

/**
 * @description: Decrease one running srd task
 */
void decrease_running_srd_task()
{
    g_running_srd_task_mutex.lock();
    if (g_running_srd_task > 0)
    {
        g_running_srd_task--;
    }
    g_running_srd_task_mutex.unlock();
}
