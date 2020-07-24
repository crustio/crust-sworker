#include "ECalls.h"
#include "tbb/concurrent_vector.h"
#include "tbb/concurrent_unordered_map.h"

// Enclave task structure
typedef struct _enclave_task_t {
    // Task id to task running number mapping
    std::unordered_map<std::string, int> task_info;
    uint32_t timeout = 0;
} enclave_task_t;

// Task info, invoked enclave function to enclave task_info mapping
tbb::concurrent_unordered_map<std::string, enclave_task_t> g_running_task_um;
// Record running task number
int g_running_task_num;
// Lock to ensure mutex
std::mutex g_task_mutex;
// Task priority map, lower number represents higher priority
std::unordered_map<std::string, int> g_task_priority_um = {
    {"Ecall_restore_metadata", 0},
    {"Ecall_gen_key_pair", 0},
    {"Ecall_set_chain_account_id", 0},
    {"Ecall_cmp_chain_account_id", 0},
    {"Ecall_get_quote_report", 0},
    {"Ecall_verify_iasreport", 0},
    {"Ecall_gen_sgx_measurement", 0},
    {"Ecall_main_loop", 0},
    {"Ecall_get_signed_work_report", 0},
    {"Ecall_get_signed_order_report", 0},
    {"Ecall_confirm_file", 0},
    {"Ecall_delete_file", 0},
    {"Ecall_seal_file", 1},
    {"Ecall_unseal_file", 1},
    {"Ecall_srd_decrease", 1},
    {"Ecall_srd_update_metadata", 1},
    {"Ecall_srd_set_change", 1},
    {"Ecall_srd_increase", 2},
    {"Ecall_id_get_info", 3},
    {"Ecall_get_workload", 3},
};
// Mapping of Enclave task to its block tasks
std::unordered_map<std::string, std::unordered_set<std::string>> g_block_tasks_um = {
    {
        "Ecall_srd_increase", 
        {
            "Ecall_seal_file", 
            "Ecall_unseal_file", 
            "Ecall_get_signed_work_report",
            "Ecall_get_signed_order_report",
            "Ecall_confirm_file",
        }
    },
    {
        "Ecall_confirm_file",
        {
            "Ecall_get_signed_work_report",
        }
    }
};
// Indicate number of each priority task, higher index represents lower priority
tbb::concurrent_vector<int> g_waiting_task_sum_v(4, 0);
// Ecall function name to invoked number mapping
tbb::concurrent_unordered_map<std::string, int> g_invoked_ecalls_um;
// Waiting time(million seconds) for different priority task
std::vector<uint32_t> g_task_wait_time_v = {100, 10000, 100000, 1000000};

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Get higher priority task number
 * @param cur_prio -> current priority
 * @return: The higher task number
 * */
int get_higher_prio_waiting_task_num(int priority)
{
    int ret = 0;
    while (--priority >= 0)
    {
        ret += g_waiting_task_sum_v[priority];
    }

    return ret;
}

/**
 * @description: Set task sleep by priority
 * @param priority -> Task priority
 * */
void task_sleep(int priority)
{
    usleep(g_task_wait_time_v[priority]);
}

/**
 * @description: Try to get permission to enclave
 * @param name -> Pointer to invoke function name
 * @return: Get status
 * */
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
    // Increase corresponding task queue
    g_waiting_task_sum_v[cur_task_prio]++;
    // Increase corresponding invoked ecall
    g_invoked_ecalls_um[tname]++;

    // ----- Task scheduling ----- //
    while (true)
    {
        // Check if current task's blocking task is running
        if (g_block_tasks_um.find(tname) != g_block_tasks_um.end())
        {
            for (auto btask : g_block_tasks_um[tname])
            {
                if (g_invoked_ecalls_um[btask] > 0)
                {
                    sgx_status = SGX_ERROR_DEVICE_BUSY;
                    goto loop;
                }
            }
        }

        if (g_running_task_num < ENC_MAX_THREAD_NUM)
        {
            // Try to get lock
            if (!g_task_mutex.try_lock())
                goto loop;

            // If cannot get enclave resource
            // 1. Current task number equal or larger than ENC_MAX_THREAD_NUM
            // 2. Current task priority lower than highest level and remaining resource less than ENC_RESERVED_THREAD_NUM
            // 3. There exists higher priority task waiting
            if (g_running_task_num >= ENC_MAX_THREAD_NUM 
                    || (cur_task_prio > ENC_HIGHEST_PRIORITY && ENC_MAX_THREAD_NUM - g_running_task_num <= ENC_RESERVED_THREAD_NUM)
                    || get_higher_prio_waiting_task_num(cur_task_prio) - ENC_PERMANENT_TASK_NUM > 0)
            {
                g_task_mutex.unlock();
                if (cur_task_prio > ENC_PRIO_TIMEOUT_THRESHOLD)
                {
                    p_log->debug("task:%s(thread id:%s) blocked because of SGX busy!\n", name, this_id.c_str());
                }
                goto loop;
            }
            // Get enclave resource
            if (g_running_task_um.count(this_id) == 0)
            {
                // This situation happens when an ecall invokes an ocall
                // and the ocall invokes an ecall again.
                (g_running_task_um[this_id].task_info)[tname] = 1;
                g_running_task_num++;
            }
            else
            {
                // This thread is running, this situation happens when a ocall invokes ecall function
                (g_running_task_um[this_id].task_info)[tname]++;
            }
            g_task_mutex.unlock();
            break;
        }

    loop:
        // Check if current task is a tiemout task
        if (cur_task_prio > ENC_PRIO_TIMEOUT_THRESHOLD)
        {
            timeout++;
            if (timeout >= ENC_TASK_TIMEOUT)
            {
                g_running_task_um.unsafe_erase(this_id);
                p_log->debug("task:%s(thread id:%s) timeout!\n", name, this_id.c_str());
                sgx_status = SGX_ERROR_SERVICE_TIMEOUT;
                break;
            }
        }
        task_sleep(cur_task_prio);
    }

    // Decrease waiting task queue
    g_waiting_task_sum_v[cur_task_prio]--;

    // If invoked failed, decrease invoke ecall queue
    if (SGX_SUCCESS != sgx_status)
    {
        g_invoked_ecalls_um[tname]--;
    }

    return sgx_status;
}

/**
 * @description: Free enclave
 * @param name -> Pointer to invoke function name
 * */
void free_enclave(const char *name)
{
    g_task_mutex.lock();
    std::string tname = std::string(name);
    std::thread::id tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << tid;
    std::string this_id = ss.str();
    g_running_task_um.unsafe_erase(this_id);
    g_running_task_num--;
    g_task_mutex.unlock();

    // Decrease corresponding invoked ecall
    g_invoked_ecalls_um[tname]--;
}

/**
 * @description: Show enclave thread info
 * @return: Task information
 * */
std::string show_enclave_thread_info()
{
    json::JSON task_info_json;
    for (auto it : g_running_task_um)
    {
        for (auto iter : it.second.task_info)
        {
            task_info_json[iter.first] = task_info_json[iter.first].ToInt() + iter.second;
        }
    }

    return task_info_json.dump();
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
 * @return: Restore status
 * */
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
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 * @return: Compare status
 * */
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
 * @description: A wrapper function, Set crust account id
 * @param account_id (in) -> Pointer to account id
 * @param len -> Account id length
 * @return: Set status
 * */
sgx_status_t Ecall_set_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_set_chain_account_id(eid, status, account_id, len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Get signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @param p_signature (out) -> sig by tee
 * @param report (out) -> work report string
 * @param report_len (in) -> work report string length
 * @return: sign status
 * */
sgx_status_t Ecall_get_signed_work_report(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_signed_work_report(eid, status, block_hash, block_height);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate ecc key pair and store it in enclave
 * @return: generate status
 * */
sgx_status_t Ecall_gen_key_pair(sgx_enclave_id_t eid, sgx_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_key_pair(eid, status);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, get sgx report, our generated public key contained
 *  in report data
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 * @return: get sgx report status
 * */
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
 * @return: generate status
 * */
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
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 * @return: verify status
 * */
sgx_status_t Ecall_verify_iasreport(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_verify_iasreport(eid, status, IASReport, len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Seal file according to given path and return new MerkleTree
 * @param p_tree (in) -> Pointer to MerkleTree json structure buffer 
 * @param tree_len -> MerkleTree json structure buffer length
 * @param path (in) -> Reference to file path
 * @param p_new_path (out) -> Pointer to sealed data path
 * @param path_len -> Pointer to file path length
 * @return: Seal status
 * */
sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *p_tree, size_t tree_len, const char *path, 
        char *p_new_path , size_t path_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_seal_file(eid, status, p_tree, tree_len, path, p_new_path, path_len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Unseal file according to given path
 * @param files (in) -> Files in root directory
 * @param files_num -> Files number in root directory
 * @param p_dir (in) -> Root directory path
 * @param p_new_path (out) -> Pointer to unsealed data path
 * @param path_len -> Root dir path length
 * @return: Unseal status
 * */
sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, char **files, size_t files_num, const char *p_dir, 
        char *p_new_path, uint32_t path_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_unseal_file(eid, status, files, files_num, p_dir, p_new_path, path_len);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get signed order report
 * @return: Get status
 * */
sgx_status_t Ecall_get_signed_order_report(sgx_enclave_id_t eid, crust_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_signed_order_report(eid, status);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 * */
sgx_status_t Ecall_srd_set_change(sgx_enclave_id_t eid, long change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_set_change(eid, change);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Update srd_g_hashs
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 * */
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
 * @description: Confirm new file
 * @param hash -> New file hash
 * @return: Confirm status
 * */
sgx_status_t Ecall_confirm_file(sgx_enclave_id_t eid, crust_status_t *status, const char *hash)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_confirm_file(eid, status, hash);

    free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Delete file
 * @param hash -> File root hash
 * */
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
 * @description: Get enclave id information
 * */
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
 * */
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
