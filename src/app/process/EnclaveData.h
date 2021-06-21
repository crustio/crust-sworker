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
#include "Srd.h"

class EnclaveData
{
public:
    static EnclaveData *get_instance();

    std::string get_enclave_id_info();
    void set_enclave_id_info(std::string id_info);
    std::string get_enclave_workload();
    void set_enclave_workload(std::string workload);
    std::string get_upgrade_data();
    void set_upgrade_data(std::string data);
    upgrade_status_t get_upgrade_status();
    void set_upgrade_status(upgrade_status_t status);
    void set_workreport(const uint8_t *data, size_t data_size);
    std::string get_workreport();
    void set_srd_complete(long num);
    json::JSON get_free_space();
    // File information
    void add_file_info(const std::string &cid, std::string type, std::string info);
    std::string get_file_info(std::string cid);
    void change_file_type(const std::string &cid, std::string old_type, std::string new_type);
    std::string get_file_info_all();
    std::string get_file_info_by_type(std::string type);
    std::string _get_file_info_by_type(std::string type, std::string pad, bool raw);
    size_t get_files_size_by_type(const char *type);
    void del_file_info(std::string cid);
    void del_file_info(std::string cid, std::string type);
    bool find_file_type(std::string cid, std::string &type);
    bool find_file_type_nolock(std::string cid, std::string &type);
    void restore_file_info(const uint8_t *data, size_t data_size);
    void set_srd_info(const uint8_t *data, size_t data_size);
    json::JSON get_srd_info();
    // Get workload
    std::string gen_workload_str(long srd_task = 0);
    json::JSON gen_workload_for_print(long srd_task = 0);
    json::JSON gen_workload(long srd_task = 0);
    // For uuid and disk path
    void construct_uuid_disk_path_map();
    void set_uuid_disk_path_map(std::string uuid, std::string path);
    std::string get_disk_path(std::string uuid);
    std::string get_uuid(std::string path);
    bool is_disk_exist(std::string path);
    bool is_uuid_exist(std::string uuid);

private:
    static EnclaveData *enclavedata;
    EnclaveData()
        : enclave_id_info("")
        , enclave_workload("")
        , upgrade_data("")
        , upgrade_status(UPGRADE_STATUS_NONE) 
        , srd_complete(0) {}

    std::string get_file_info_item(json::JSON &info, bool raw);

    // Store enclave identity information
    std::string enclave_id_info;
    std::mutex enclave_id_info_mutex;
    // Store enclave workload information
    std::string enclave_workload;
    std::mutex enclave_workload_mutex;
    // Upgrade data
    std::string upgrade_data;
    std::mutex upgrade_data_mutex;
    // Upgrade status
    upgrade_status_t upgrade_status;
    std::mutex upgrade_status_mutex;
    // Srd complete
    long srd_complete;
    std::mutex srd_complete_mutex;
    // Sealed file map
    std::map<std::string, std::map<std::string, json::JSON>> sealed_file;
    std::mutex sealed_file_mutex;
    // Srd info
    json::JSON srd_info;
    std::mutex srd_info_mutex;
    // For uuid and disk path
    std::unordered_map<std::string, std::string> uuid_to_disk_path;
    std::unordered_map<std::string, std::string> disk_path_to_uuid;
    std::mutex uuid_disk_path_map_mutex;
    // For workreport
    std::string workreport;
    std::mutex workreport_mutex;
};

#endif /* !_APP_ENCLAVE_DATA_H_ */
