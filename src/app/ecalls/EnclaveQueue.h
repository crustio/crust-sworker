#ifndef _ENCLAVE_QUEUE_H_
#define _ENCLAVE_QUEUE_H_

#include <iostream>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>

#include <sgx_error.h>
#include <sgx_eid.h>

#include "Resource.h"
#include "Enclave_u.h"
#include "Log.h"
#include "EnclaveData.h"
#include "CrustStatus.h"
#include "SafeLock.h"

// Max thread number.
// Note: If you change this macro name, you should change corresponding name in Makefile
#define ENC_MAX_THREAD_NUM  30
// Reserved enclave resource for highest priority task
#define ENC_RESERVED_THREAD_NUM  1
// Threshold to trigger timeout mechanism
#define ENC_PRIO_TIMEOUT_THRESHOLD 1
// Number of running in enclave permanently
#define ENC_PERMANENT_TASK_NUM 1
// Highest priority
#define ENC_HIGHEST_PRIORITY 0
// Task timeout number
#define ENC_TASK_TIMEOUT  30


class EnclaveQueue
{
public:
    void increase_waiting_queue(std::string name);
    void decrease_waiting_queue(std::string name);
    void increase_running_queue(std::string name);
    void decrease_running_queue(std::string name);
    int get_running_ecalls_sum();
    int get_running_ecalls_num(std::string name);
    std::string get_running_ecalls_info();
    int get_higher_prio_waiting_task_num(std::string name);
    void task_sleep(int priority);
    sgx_status_t try_get_enclave(const char *name);
    void free_enclave(const char *name);
    int get_upgrade_ecalls_num();
    bool has_stopping_block_task();
    static EnclaveQueue *enclaveQueue;
    static EnclaveQueue *get_instance();

private:
    EnclaveQueue() {}
    // Task priority map, lower number represents higher priority
    std::unordered_map<std::string, int> task_priority_um = {
        {"Ecall_restore_metadata", 0},
        {"Ecall_gen_key_pair", 0},
        {"Ecall_cmp_chain_account_id", 0},
        {"Ecall_get_quote_report", 0},
        {"Ecall_verify_and_upload_identity", 0},
        {"Ecall_gen_sgx_measurement", 0},
        {"Ecall_main_loop", 0},
        {"Ecall_stop_all", 0},
        {"Ecall_gen_and_upload_work_report", 0},
        {"Ecall_gen_upgrade_data", 0},
        {"Ecall_restore_from_upgrade", 0},
        {"Ecall_enable_upgrade", 0},
        {"Ecall_disable_upgrade", 0},
        {"Ecall_delete_file",1},
        {"Ecall_validate_file", 1},
        {"Ecall_validate_srd", 1},
        {"Ecall_seal_file_start", 1},
        {"Ecall_seal_file", 1},
        {"Ecall_seal_file_end", 1},
        {"Ecall_unseal_file", 1},
        {"Ecall_srd_decrease", 1},
        {"Ecall_srd_remove_space", 1},
        {"Ecall_change_srd_task", 1},
        {"Ecall_srd_increase", 2},
        {"Ecall_id_get_info", 2},
        {"Ecall_get_workload", 3},
    };
    // Mapping of Enclave task to its block tasks, current task cannot run when there exists its block task
    std::unordered_map<std::string, std::unordered_set<std::string>> block_tasks_um = {
        {
            "Ecall_srd_increase", 
            {
                "Ecall_seal_file_start", 
                "Ecall_seal_file", 
                "Ecall_seal_file_end", 
            }
        },
    };
    // Lower priority ignore higher priority task
    std::unordered_map<std::string, std::unordered_set<std::string>> low_ignore_high_um = {
        {
            "Ecall_srd_increase",
            {
                "Ecall_unseal_file",
            }
        }
    };
    // Upgrade blocks task set1
    std::unordered_set<std::string> upgrade_blocked_task_us = {
        "Ecall_seal_file_start",
        "Ecall_seal_file",
        "Ecall_seal_file_end",
        "Ecall_unseal_file",
        "Ecall_srd_decrease",
        "Ecall_srd_increase",
        "Ecall_delete_file",
        "Ecall_srd_remove_space",
    };
    // Stopping block task
    std::vector<std::string> stop_block_task_v = {
        "Ecall_gen_and_upload_work_report",
        "Ecall_main_loop",
    };
    // Record running task number
    int running_task_num;
    std::mutex running_task_num_mutex;
    // Waiting queue item structure
    struct waiting_priority_item {
        int num;
        std::unordered_map<std::string, int> task_num_um;
    };
    // Waiting task name to number map
    std::unordered_map<int, waiting_priority_item> waiting_task_um;
    std::mutex waiting_task_um_mutex;
    // Ecall function name to running number mapping
    std::unordered_map<std::string, int> running_ecalls_um;
    std::mutex running_ecalls_mutex;
    // Waiting time(million seconds) for different priority task
    std::vector<uint32_t> task_wait_time_v = {100, 10000, 500000, 1000000};
};

#endif /* !_ENCLAVE_QUEUE_H_ */
