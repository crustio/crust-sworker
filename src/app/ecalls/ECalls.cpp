#include "ECalls.h"

// Task priority map, lower number represents higher priority
std::unordered_map<std::string, int> g_task_priority_um = {
    {"Ecall_restore_metadata", 0},
    {"Ecall_gen_key_pair", 0},
    {"Ecall_cmp_chain_account_id", 0},
    {"Ecall_get_quote_report", 0},
    {"Ecall_verify_and_upload_identity", 0},
    {"Ecall_gen_sgx_measurement", 0},
    {"Ecall_main_loop", 0},
    {"Ecall_gen_and_upload_work_report", 0},
    {"Ecall_delete_file", 0},
    {"Ecall_gen_upgrade_data", 0},
    {"Ecall_restore_from_upgrade", 0},
    {"Ecall_enable_upgrade", 0},
    {"Ecall_disable_upgrade", 0},
    {"Ecall_seal_file", 1},
    {"Ecall_unseal_file", 1},
    {"Ecall_srd_decrease", 1},
    {"Ecall_srd_update_metadata", 1},
    {"Ecall_change_srd_task", 1},
    {"Ecall_srd_increase", 2},
    {"Ecall_id_get_info", 3},
    {"Ecall_get_workload", 3},
};
// Mapping of Enclave task to its block tasks, current task cannot run when there exists its block task
std::unordered_map<std::string, std::unordered_set<std::string>> g_block_tasks_um = {
    {
        "Ecall_srd_increase", 
        {
            "Ecall_seal_file", 
            "Ecall_unseal_file", 
            "Ecall_gen_and_upload_work_report",
        }
    },
    {
        "Ecall_delete_file",
        {
            "Ecall_gen_and_upload_work_report",
        }
    },
};
// Upgrade blocks task set1
std::unordered_set<std::string> g_upgrade_blocked_task_us = {
    "Ecall_seal_file",
    "Ecall_unseal_file",
    "Ecall_srd_decrease",
    "Ecall_srd_increase",
    "Ecall_delete_file",
};
// Record running task number
int g_running_task_num;
std::mutex g_running_task_mutex;
// Indicate number of each priority task, higher index represents lower priority
std::vector<int> g_waiting_priority_sum_v(4, 0);
std::mutex g_waiting_priority_sum_mutex;
// Ecall function name to running number mapping
std::unordered_map<std::string, int> g_running_ecalls_um;
std::mutex g_running_ecalls_mutex;
// Waiting time(million seconds) for different priority task
std::vector<uint32_t> g_task_wait_time_v = {100, 10000, 500000, 1000000};

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Increase waiting queue
 * @param name -> Waiting task name
 */
void increase_waiting_queue(std::string name)
{
    g_waiting_priority_sum_mutex.lock();
    g_waiting_priority_sum_v[g_task_priority_um[name]]++;
    g_waiting_priority_sum_mutex.unlock();
}

/**
 * @description: Decrease waiting queue
 * @param name -> Waiting task name
 */
void decrease_waiting_queue(std::string name)
{
    SafeLock sl(g_waiting_priority_sum_mutex);
    sl.lock();
    int priority = g_task_priority_um[name];
    if (g_waiting_priority_sum_v[priority] == 0)
    {
        p_log->warn("Priority:%d task sum is 0.\n", priority);
        return;
    }
    g_waiting_priority_sum_v[priority]--;
}

/**
 * @description: Increase indicated ecall's running number
 * @param name -> Ecall's name
 */
void increase_running_queue(std::string name)
{
    g_running_ecalls_mutex.lock();
    if (g_running_ecalls_um.count(name) == 0)
    {
        g_running_ecalls_um[name] = 0;
    }
    g_running_ecalls_um[name]++;
    g_running_ecalls_mutex.unlock();
}

/**
 * @description: Decrease indicated ecall's running number
 * @param name -> Ecall's name
 */
void decrease_running_queue(std::string name)
{
    SafeLock sl(g_running_ecalls_mutex);
    sl.lock();
    if (g_running_ecalls_um[name] == 0)
    {
        p_log->warn("Invoking ecall:%s num is 0.\n", name.c_str());
        return;
    }
    g_running_ecalls_um[name]--;
    sl.unlock();
}

/**
 * @description: Get running tasks total num
 * @return: Running tasks total num
 */
int get_running_ecalls_sum()
{
    g_running_ecalls_mutex.lock();
    int res = g_running_task_num;
    g_running_ecalls_mutex.unlock();

    return res;
}

/**
 * @description: Get running ecalls number
 * @param name -> Running ecall's name
 * @return: Running ecall's number
 */
int get_running_ecalls_num(std::string name)
{
    g_running_ecalls_mutex.lock();
    int ans = g_running_ecalls_um[name];
    g_running_ecalls_mutex.unlock();

    return ans;
}

/**
 * @description: Get running tasks info
 * @return: Running tasks info
 */
std::string get_running_ecalls_info()
{
    g_running_ecalls_mutex.lock();
    json::JSON info_json;
    for (auto item : g_running_ecalls_um)
    {
        if (item.second != 0)
        {
            info_json[item.first] = item.second;
        }
    }
    g_running_ecalls_mutex.unlock();

    return info_json.dump();
}

/**
 * @description: Get higher priority task number
 * @param cur_prio -> current priority
 * @return: The higher task number
 */
int get_higher_prio_waiting_task_num(int priority)
{
    g_waiting_priority_sum_mutex.lock();
    int ret = 0;
    while (--priority >= 0)
    {
        ret += g_waiting_priority_sum_v[priority];
    }
    g_waiting_priority_sum_mutex.unlock();

    return ret;
}

/**
 * @description: Set task sleep by priority
 * @param priority -> Task priority
 */
void task_sleep(int priority)
{
    usleep(g_task_wait_time_v[priority]);
}

/**
 * @description: Try to get permission to enclave
 * @param name -> Pointer to invoke function name
 * @return: Get status
 */
sgx_status_t try_get_enclave(const char *name)
{
    std::string tname(name);
    std::thread::id tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << tid;
    std::string this_id = ss.str();
    uint32_t timeout = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;

    // Get current task priority
    int cur_task_prio = g_task_priority_um[tname];
    // Increase corresponding waiting ecall
    increase_waiting_queue(tname);

    // ----- Task scheduling ----- //
    while (true)
    {
        // Check if current task's blocking task is running
        if (g_block_tasks_um.find(tname) != g_block_tasks_um.end())
        {
            for (auto btask : g_block_tasks_um[tname])
            {
                if (get_running_ecalls_num(btask) > 0)
                {
                    goto loop;
                }
            }
        }

        // Following situations cannot get enclave resource:
        // 1. Current task number equal or larger than ENC_MAX_THREAD_NUM
        // 2. Current task priority lower than highest level and remaining resource less than ENC_RESERVED_THREAD_NUM
        // 3. There exists higher priority task waiting
        g_running_task_mutex.lock();
        if (g_running_task_num >= ENC_MAX_THREAD_NUM 
                || (cur_task_prio > ENC_HIGHEST_PRIORITY && ENC_MAX_THREAD_NUM - g_running_task_num <= ENC_RESERVED_THREAD_NUM)
                || get_higher_prio_waiting_task_num(cur_task_prio) - ENC_PERMANENT_TASK_NUM > 0)
        {
            g_running_task_mutex.unlock();
            goto loop;
        }
        g_running_task_num++;
        g_running_task_mutex.unlock();

        // Add current task to running queue and quit
        increase_running_queue(tname);
        break;

    loop:
        // Check if current task is a tiemout task
        if (cur_task_prio > ENC_PRIO_TIMEOUT_THRESHOLD)
        {
            timeout++;
            if (timeout >= ENC_TASK_TIMEOUT)
            {
                p_log->debug("task:%s(thread id:%s) needs to make way for other tasks.\n", name, this_id.c_str());
                sgx_status = SGX_ERROR_SERVICE_TIMEOUT;
                break;
            }
        }
        task_sleep(cur_task_prio);
    }

    // Decrease corresponding waiting ecall
    decrease_waiting_queue(tname);

    return sgx_status;
}

/**
 * @description: Free enclave
 * @param name -> Pointer to invoke function name
 */
void free_enclave(const char *name)
{
    g_running_task_mutex.lock();
    g_running_task_num--;
    g_running_task_mutex.unlock();

    decrease_running_queue(name);
}

/**
 * @description: Get blocking upgrade ecalls' number
 * @return: Blocking ecalls' number
 */
int get_upgrade_ecalls_num()
{
    int block_task_num = 0;
    for (auto task : g_upgrade_blocked_task_us)
    {
        block_task_num += get_running_ecalls_num(task);
    }

    return block_task_num;
}

/**
 * @description: A wrapper function, seal one G srd files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
sgx_status_t Ecall_srd_increase(sgx_enclave_id_t eid, const char* path)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_increase(eid, path);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, decrease srd files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
sgx_status_t Ecall_srd_decrease(sgx_enclave_id_t eid, size_t *size, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_decrease(eid, size, change);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, ecall main loop
 */
sgx_status_t Ecall_main_loop(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_main_loop(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Restore enclave data from file
 * @param status -> Pointer to restore result status
 */
sgx_status_t Ecall_restore_metadata(sgx_enclave_id_t eid, crust_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_restore_metadata(eid, status);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Compare chain account with enclave's
 * @param status -> Pointer to compare result status
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 */
sgx_status_t Ecall_cmp_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_cmp_chain_account_id(eid, status, account_id, len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Get signed validation report
 * @param status -> Pointer to get result status
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 */
sgx_status_t Ecall_gen_and_upload_work_report(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_and_upload_work_report(eid, status, block_hash, block_height);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate ecc key pair and store it in enclave
 */
sgx_status_t Ecall_gen_key_pair(sgx_enclave_id_t eid, sgx_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_key_pair(eid, status, account_id, len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, get sgx report, our generated public key contained
 *  in report data
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 */
sgx_status_t Ecall_get_quote_report(sgx_enclave_id_t eid, sgx_status_t *status, sgx_report_t *report, sgx_target_info_t *target_info)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_quote_report(eid, status, report, target_info);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate current code measurement
 */
sgx_status_t Ecall_gen_sgx_measurement(sgx_enclave_id_t eid, sgx_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_sgx_measurement(eid, status);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, verify IAS report
 * @param status -> Pointer to verify result status
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 */
sgx_status_t Ecall_verify_and_upload_identity(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_verify_and_upload_identity(eid, status, IASReport, len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Seal file according to given path and return new MerkleTree
 * @param status -> Pointer to seal result status
 * @param cid -> Ipfs content id
 * @param file_size -> Pointer to sealed file size
 */
sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *cid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_seal_file(eid, status, cid);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Unseal file according to given path
 * @param status -> Pointer to unseal result status
 * @param files (in) -> Files in root directory
 * @param files_num -> Files number in root directory
 * @param p_dir (in) -> Root directory path
 * @param p_new_path (out) -> Pointer to unsealed data path
 * @param path_len -> Root dir path length
 */
sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *data, size_t data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_unseal_file(eid, status, data, data_size);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 */
sgx_status_t Ecall_change_srd_task(sgx_enclave_id_t eid, crust_status_t *status, long change, long *real_change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_change_srd_task(eid, status, change, real_change);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Update srd_g_hashs
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 */
sgx_status_t Ecall_srd_update_metadata(sgx_enclave_id_t eid, const char *hashs, size_t hashs_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_update_metadata(eid, hashs, hashs_len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Delete file
 * @param status -> Pointer to delete result status
 * @param hash -> File root hash
 */
sgx_status_t Ecall_delete_file(sgx_enclave_id_t eid, crust_status_t *status, const char *hash)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_delete_file(eid, status, hash);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Generate upgrade metadata
 * @param status -> Pointer to generate result status
 */
sgx_status_t Ecall_gen_upgrade_data(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_upgrade_data(eid, status, block_height);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Generate upgrade metadata
 * @param status -> Pointer to metadata
 */
sgx_status_t Ecall_restore_from_upgrade(sgx_enclave_id_t eid, crust_status_t *status, const char *meta, size_t meta_len, size_t total_size, bool transfer_end)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_restore_from_upgrade(eid, status, meta, meta_len, total_size, transfer_end);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Enable upgrade
 * @param block_height -> Current block height
 */
sgx_status_t Ecall_enable_upgrade(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_enable_upgrade(eid, status, block_height);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Disable upgrade
 */
sgx_status_t Ecall_disable_upgrade(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_disable_upgrade(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get enclave id information
 */
sgx_status_t Ecall_id_get_info(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_id_get_info(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get workload
 */
sgx_status_t Ecall_get_workload(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_workload(eid);

    free_enclave(__FUNCTION__);

    return ret;
}
