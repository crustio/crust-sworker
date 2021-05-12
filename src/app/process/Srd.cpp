#include "Srd.h"
#include "ECalls.h"

crust::Log *p_log = crust::Log::get_instance();

size_t g_running_srd_task = 0;
std::mutex g_running_srd_task_mutex;

extern sgx_enclave_id_t global_eid;

/**
 * @description: Check or initilize disk
 * @param path -> Disk path
 * @return: Check or init result
 */
bool check_or_init_disk(std::string path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    EnclaveData *ed = EnclaveData::get_instance();
    Config *p_config = Config::get_instance();

    // Check if given path is in the system disk
    if (!p_config->is_valid_or_normal_disk(path))
    {
        return false;
    }

    // Check if uuid file exists
    std::string uuid_file = path + DISK_UUID_FILE;
    if (access(uuid_file.c_str(), R_OK) != -1)
    {
        // Check if uuid to disk path mapping existed
        if (!ed->is_disk_exist(path))
        {
            uint8_t *p_data = NULL;
            size_t data_sz = 0;
            if (CRUST_SUCCESS != (crust_status = get_file(uuid_file.c_str(), &p_data, &data_sz)))
            {
                p_log->err("Get existed path:%s uuid failed! Error code:%lx\n", uuid_file.c_str(), crust_status);
            }
            else
            {
                ed->set_uuid_disk_path_map(reinterpret_cast<const char *>(p_data), path);
                free(p_data);
                return true;
            }
        }
        else
        {
            return true;
        }
    }
    else
    {
        if (ed->is_disk_exist(path))
        {
            std::string uuid = ed->get_uuid(path);
            crust_status = save_file_ex(uuid_file.c_str(), reinterpret_cast<const uint8_t *>(uuid.c_str()), uuid.size(), 0444, SF_CREATE_DIR);
            if (CRUST_SUCCESS != crust_status)
            {
                p_log->err("Save uuid file failed! Error code:%lx\n", crust_status);
                return false;
            }
        }
    }

    // Create current disk
    std::string srd_dir = path + DISK_SRD_DIR;
    if (CRUST_SUCCESS != create_directory(srd_dir))
    {
        p_log->err("Cannot create dir:%s\n", srd_dir.c_str());
        return false;
    }

    // Create uuid file
    uint8_t *buf = (uint8_t *)malloc(UUID_LENGTH);
    Defer def_buf([&buf](void) { free(buf); });
    memset(buf, 0, UUID_LENGTH);
    read_rand(buf, UUID_LENGTH);
    std::string uuid = hexstring_safe(buf, UUID_LENGTH);
    crust_status = save_file_ex(uuid_file.c_str(), reinterpret_cast<const uint8_t *>(uuid.c_str()), uuid.size(), 0444, SF_CREATE_DIR);
    if (CRUST_SUCCESS != crust_status)
    {
        p_log->err("Save uuid file failed! Error code:%lx\n", crust_status);
        return false;
    }

    // Set uuid to data path information
    ed->set_uuid_disk_path_map(uuid, path);

    return true;
}

/**
 * @description: Get srd disks info according to configure
 * @param change -> Reference to changed task, will be modified to left srd task
 * @return: A path to assigned size map
 */
json::JSON get_increase_srd_info_r(long &change)
{
    size_t true_srd_capacity = 0;
    // Get multi-disk info
    Config *p_config = Config::get_instance();
    EnclaveData *ed = EnclaveData::get_instance();
    json::JSON disk_info_json;

    // Create path
    for (auto path : p_config->get_data_paths())
    {
        if (check_or_init_disk(path))
        {
            std::string uuid = ed->get_uuid(path);
            // Calculate free disk
            long srd_reserved_space = get_reserved_space();
            json::JSON tmp_info_json;
            tmp_info_json[WL_DISK_AVAILABLE] = get_avail_space_under_dir_g(path);
            tmp_info_json[WL_DISK_VOLUME] = get_total_space_under_dir_g(path);
            if (tmp_info_json[WL_DISK_AVAILABLE].ToInt() <= srd_reserved_space)
            {
                tmp_info_json[WL_DISK_AVAILABLE_FOR_SRD] = 0;
            }
            else
            {
                tmp_info_json[WL_DISK_AVAILABLE_FOR_SRD] = tmp_info_json[WL_DISK_AVAILABLE].ToInt() - srd_reserved_space;
            }
            tmp_info_json[WL_DISK_UUID] = uuid;
            tmp_info_json[WL_DISK_PATH] = path;
            true_srd_capacity += tmp_info_json[WL_DISK_AVAILABLE_FOR_SRD].ToInt();
            disk_info_json.append(tmp_info_json);
        }
    }

    // Get to be used info
    bool avail = true;
    while (change > 0 && avail)
    {
        avail = false;
        for (int i = 0; i < disk_info_json.size() && change > 0; i++)
        {
            if (disk_info_json[i][WL_DISK_AVAILABLE_FOR_SRD].ToInt() - disk_info_json[i][WL_DISK_USE].ToInt() > 0)
            {
                disk_info_json[i][WL_DISK_USE].AddNum(1);
                change--;
                avail = true;
            }
        }
    }

    return disk_info_json;
}

/**
 * @description: Wrapper for get_increase_srd_info_r
 * @param change -> Reference to srd task, will be changed and modified to left srd task
 * @return: Srd info in json format
 */
json::JSON get_increase_srd_info(long &change)
{
    return get_increase_srd_info_r(change);
}

/**
 * @description: Wrapper for get_increase_srd_info_r
 * @return: Srd info in json format
 */
json::JSON get_disk_info()
{
    long c = 0;
    return get_increase_srd_info_r(c);
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
        long left_task = change;
        json::JSON disk_info_json = get_increase_srd_info(left_task);
        long true_increase = change - left_task;
        // Add left change to next srd, if have
        if (left_task > 0)
        {
            p_log->warn("No enough space for %ldG srd, can only do %ldG srd.\n", change, true_increase);
            crust_status = CRUST_SRD_NUMBER_EXCEED;
        }
        if (true_increase <= 0)
        {
            //p_log->warn("No available space for srd!\n");
            return CRUST_SRD_NUMBER_EXCEED;
        }
        set_running_srd_task(true_increase);
        // Print disk info
        for (auto info : disk_info_json.ArrayRange())
        {
            if (info[WL_DISK_USE].ToInt() > 0)
            {
                p_log->info("Available space is %ldG in '%s', this turn will use %ldG space\n", 
                        info[WL_DISK_AVAILABLE_FOR_SRD].ToInt(),
                        info[WL_DISK_PATH].ToString().c_str(),
                        info[WL_DISK_USE].ToInt());
            }
        }
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);

        // ----- Do srd ----- //
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        ctpl::thread_pool pool(p_config->srd_thread_num);
        std::vector<std::shared_ptr<std::future<crust_status_t>>> tasks_v;
        long task = true_increase;
        while (task > 0)
        {
            for (int i = 0; i < disk_info_json.size() && task > 0; i++, task--)
            {
                sgx_enclave_id_t eid = global_eid;
                std::string uuid = disk_info_json[i][WL_DISK_UUID].ToString();
                tasks_v.push_back(std::make_shared<std::future<crust_status_t>>(pool.push([&eid, uuid](int /*id*/){
                    sgx_status_t sgx_status = SGX_SUCCESS;
                    crust_status_t increase_ret = CRUST_SUCCESS;
                    if (SGX_SUCCESS != (sgx_status = Ecall_srd_increase(eid, &increase_ret, uuid.c_str()))
                            || CRUST_SUCCESS != increase_ret)
                    {
                        // If failed, add current task to next turn
                        long real_change = 0;
                        crust_status_t change_ret = CRUST_SUCCESS;
                        Ecall_change_srd_task(global_eid, &change_ret, 1, &real_change);
                        sgx_status = SGX_ERROR_UNEXPECTED;
                    }
                    if (SGX_SUCCESS != sgx_status)
                    {
                        increase_ret = CRUST_UNEXPECTED_ERROR;
                    }
                    decrease_running_srd_task();
                    return increase_ret;
                })));
            }
        }
        // Wait for srd task
        size_t srd_success_num = 0;
        for (auto it : tasks_v)
        {
            try 
            {
                if (CRUST_SUCCESS == it->get())
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

        if (srd_success_num < (size_t)true_increase)
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
    Config *p_config = Config::get_instance();
    sgx_status_t sgx_status = SGX_SUCCESS;
    size_t check_interval = 10;

    while (true)
    {
        if (UPGRADE_STATUS_EXIT == EnclaveData::get_instance()->get_upgrade_status())
        {
            p_log->info("Stop srd check reserved for exit...\n");
            return;
        }

        long srd_reserved_space = get_reserved_space();
        // Lock srd_info
        EnclaveData *ed = EnclaveData::get_instance();
        json::JSON srd_del_json;
        json::JSON srd_info_json = ed->get_srd_info();
        for (auto path : p_config->get_data_paths())
        {
            size_t avail_space = get_avail_space_under_dir_g(path);
            long del_space = 0;
            if ((long)avail_space < srd_reserved_space)
            {
                std::string uuid = ed->get_uuid(path);
                del_space = std::min((long)(srd_reserved_space - avail_space), (long)srd_info_json[WL_SRD_DETAIL][uuid].ToInt());
                srd_del_json[uuid].AddNum(del_space);
            }
        }

        // Do remove
        if (srd_del_json.size() > 0)
        {
            std::string srd_del_str = srd_del_json.dump();
            remove_char(srd_del_str, ' ');
            remove_char(srd_del_str, '\\');
            remove_char(srd_del_str, '\n');
            if (SGX_SUCCESS != Ecall_srd_remove_space(global_eid, srd_del_str.c_str(), srd_del_str.size()))
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
    return DEFAULT_SRD_RESERVED;
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
