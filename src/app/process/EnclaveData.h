#ifndef _APP_ENCLAVE_DATA_H_
#define _APP_ENCLAVE_DATA_H_

#include <stdio.h>
#include <string>
#include <mutex>
#include <unordered_map>

#include "Resource.h"
#include "SafeLock.h"
#include "Log.h"
#include "Common.h"
#include "DataBase.h"
#include "Json.hpp"

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
    void add_unsealed_data(std::string root, uint8_t *data, size_t data_size);
    std::string get_unsealed_data(std::string root);
    void del_unsealed_data(std::string root);
    // Sealed information
    void add_sealed_file_info(std::string cid, std::string info);
    std::string get_sealed_file_info(std::string cid);
    std::string get_sealed_file_info_all();
    void del_sealed_file_info(std::string cid);
    bool is_sealed_file_dup(std::string cid, bool locked = true);
    void restore_sealed_file_info();

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
    // Unsealed data map
    std::unordered_map<std::string, std::pair<uint8_t *, size_t>> unsealed_data_um;
    std::mutex unsealed_data_mutex;
    // Sealed file map
    json::JSON sealed_file;
    std::mutex sealed_file_mutex;
};

#endif /* !_APP_ENCLAVE_DATA_H_ */
