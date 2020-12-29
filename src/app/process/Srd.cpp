#include "Srd.h"
#include "ECalls.h"
#include "Ctpl.h"
#include "HttpClient.h"

crust::Log *p_log = crust::Log::get_instance();

size_t g_srd_reserved_space = DEFAULT_SRD_RESERVED;

extern sgx_enclave_id_t global_eid;

/**
 * @description: Get srd disks info according to configure
 * @param true_srd_capacity -> True assigned size
 * @return: A path to assigned size map
 */
json::JSON get_increase_srd_info(size_t &true_srd_capacity)
{
    // Get multi-disk info
    Config *p_config = Config::get_instance();
    json::JSON disk_info_json;
    long srd_reserved_space = get_reserved_space();
    // Create path
    if (create_directory(p_config->srd_path))
    {
        // Calculate free disk
        disk_info_json["available"] = get_avail_space_under_dir_g(p_config->srd_path);
        disk_info_json["total"] = get_total_space_under_dir_g(p_config->srd_path);
        if (disk_info_json["available"].ToInt() <= srd_reserved_space)
        {
            disk_info_json["available"] = 0;
        }
        else
        {
            disk_info_json["available"] = disk_info_json["available"].ToInt() - srd_reserved_space;
        }
        true_srd_capacity = std::min((size_t)disk_info_json["available"].ToInt(), true_srd_capacity);
        disk_info_json["increased"] = true_srd_capacity;
    }
    else
    {
        true_srd_capacity = 0;
    }

    return disk_info_json;
}

/**
 * @description: Change SRD space
 * @param change -> SRD space number
 */
void srd_change(long change)
{
    Config *p_config = Config::get_instance();

    if (change > 0)
    {
        size_t true_increase = change;
        json::JSON disk_info_json = get_increase_srd_info(true_increase);
        // Add left change to next srd, if have
        if (change > (long)true_increase)
        {
            p_log->warn("No enough space for %ldG srd, can only do %ldG srd.\n", change, true_increase);
        }
        if (true_increase == 0)
        {
            //p_log->warn("No available space for srd!\n");
            return;
        }
        // Print disk info
        p_log->info("Available space is %ldG in '%s' folder, this turn will use %ldG space\n", 
                disk_info_json["available"].ToInt(),
                p_config->srd_path.c_str(),
                disk_info_json["increased"].ToInt());
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
                if (SGX_SUCCESS != Ecall_srd_increase(eid))
                {
                    // If failed, add current task to next turn
                    crust_status_t crust_status = CRUST_SUCCESS;
                    long real_change = 0;
                    Ecall_change_srd_task(global_eid, &crust_status, 1, &real_change);
                    return SGX_ERROR_UNEXPECTED;
                }
                return SGX_SUCCESS;
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
        Ecall_srd_decrease(global_eid, &true_decrease, (size_t)-change);
        p_log->info("Decrease %luG srd successfully.\n", true_decrease);
    }
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
    int check_interval = 10;

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
            del_space = std::min((long)(srd_reserved_space - avail_space), (long)srd_info_json["assigned"].ToInt());
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
