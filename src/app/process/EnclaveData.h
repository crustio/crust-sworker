#ifndef _APP_ENCLAVE_DATA_H_
#define _APP_ENCLAVE_DATA_H_

#include <stdio.h>
#include <string>
#include <mutex>
#include <unordered_map>

#include "Resource.h"
#include "SafeLock.h"
#include "Log.h"

class EnclaveData
{
public:
    static EnclaveData *enclavedata;
    static EnclaveData *get_instance();

    std::string get_enclave_id_info();
    void set_enclave_id_info(std::string id_info);
    std::string get_enclave_workload();
    void set_enclave_workload(std::string workload);
    std::string get_upgrade_data();
    void set_upgrade_data(std::string data);
    upgrade_status_t get_upgrade_status();
    void set_upgrade_status(upgrade_status_t status);
    void add_sealed_tree(std::string root, std::string tree);
    std::string get_sealed_tree(std::string root);
    void del_sealed_tree(std::string root);

private:
    EnclaveData()
        : enclave_id_info("")
        , enclave_workload("")
        , upgrade_data("")
        , upgrade_status(UPGRADE_STATUS_NONE) {}

    // Store enclave identity information
    std::string enclave_id_info;
    // Store enclave workload information
    std::string enclave_workload;
    // Upgrade data
    std::string upgrade_data;
    // Upgrade status
    upgrade_status_t upgrade_status;
    // Upgrade status mutex
    std::mutex upgrade_status_mutex;
    // Sealed tree map
    std::unordered_map<std::string, std::string> sealed_tree_map;
    std::mutex sealed_tree_mutex;
};

#endif /* !_APP_ENCLAVE_DATA_H_ */
