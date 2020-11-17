#ifndef _CRUST_WORKLOAD_H_
#define _CRUST_WORKLOAD_H_

#include <utility>
#include <vector>
#include <list>
#include <string>
#include <map>
#include <unordered_map>
#include <set>
#include "sgx_trts.h"
#include "EUtils.h"
#include "Enclave_t.h"
#include "sgx_thread.h"
#include "Persistence.h"
#include "EJson.h"
#include "Identity.h"
#include "Srd.h"
#include "Parameter.h"

// Show information
std::map<char, std::string> g_file_status = {
    {FILE_STATUS_UNCONFIRMED, "unconfirmed"},
    {FILE_STATUS_VALID, "valid"},
    {FILE_STATUS_LOST, "lost"},
    {FILE_STATUS_DELETED, "deleted"}
};

class Workload
{
public:
    std::map<std::string, std::vector<uint8_t*>> srd_path2hashs_m; // used to store all G srd file collection' hashs

    std::vector<json::JSON> checked_files; // Files have been added into checked queue
    std::vector<json::JSON> new_files; // Files have not been confirmed
    std::set<size_t> reported_files_idx; // File indexes reported this turn of workreport
    sgx_ec256_public_t pre_pub_key; // Old version's public key
    
    // Basic
    static Workload *workload;
    static Workload *get_instance();
    ~Workload();
    std::string get_workload(void);
    void clean_srd_buffer();
    void add_new_file(json::JSON file);
    void set_srd_info(std::string path, long change);
    json::JSON get_srd_info();
    json::JSON gen_workload_info();

    // For persistence
    crust_status_t serialize_srd(uint8_t **p_data, size_t *data_size);
    crust_status_t serialize_file(uint8_t **p_data, size_t *data_size);
    crust_status_t restore_srd(json::JSON g_hashs);
    void restore_file(json::JSON file_json);

    // For report
    void report_add_validated_proof();
    void report_reduce_validated_proof();
    bool report_has_validated_proof();
    void set_report_file_flag(bool flag);
    bool get_report_file_flag();
    void set_restart_flag();
    void reduce_restart_flag();
    bool get_restart_flag();
    void handle_report_result();
    crust_status_t try_report_work(size_t block_height);

    // For upgrade
    void set_upgrade(sgx_ec256_public_t pub_key);
    bool is_upgrade();
    void set_upgrade_status(enc_upgrade_status_t status);
    enc_upgrade_status_t get_upgrade_status();

    // For workload spec
    void set_wl_spec(char file_status, int change);
    void set_wl_spec(char file_status, char related_file_status, int change);
    const json::JSON &get_wl_spec();
    void restore_wl_spec_info(std::string data);

    // For identity
    void set_account_id(std::string account_id);
    std::string get_account_id();
    // Key pair
    bool try_get_key_pair();
    const sgx_ec256_public_t& get_pub_key();
    const sgx_ec256_private_t& get_pri_key();
    void set_key_pair(ecc_key_pair id_key_pair);
    const ecc_key_pair& get_key_pair();
    // MR enclave
    void set_mr_enclave(sgx_measurement_t mr);
    const sgx_measurement_t& get_mr_enclave();
    // Report height
    void set_report_height(size_t height);
    size_t get_report_height();

    sgx_thread_mutex_t ocall_wr_mutex = SGX_THREAD_MUTEX_INITIALIZER; // Workreport mutex
    sgx_thread_mutex_t ocall_wl_mutex = SGX_THREAD_MUTEX_INITIALIZER; // Workload mutex
    sgx_thread_mutex_t ocall_upgrade_mutex = SGX_THREAD_MUTEX_INITIALIZER; // Upgrade mutex

private:
    Workload();

    std::string account_id; // Chain account id
    ecc_key_pair id_key_pair; // Identity key pair
    bool is_set_key_pair = false; // Check if key pair has been generated
    sgx_measurement_t mr_enclave; // Enclave code measurement
    size_t report_height = 0; // Identity report height, Used to check current block head out-of-date
    int restart_flag = 0;// Used to indicate whether it is the first report after restart

    int validated_proof = 0; // Generating workreport will decrease this value, while validating will increase it
    sgx_thread_mutex_t validated_mutex = SGX_THREAD_MUTEX_INITIALIZER;

    bool is_upgrading = false; // Indicate if upgrade is doing

    bool report_files; // True indicates reporting files this turn, false means not report
    json::JSON srd_info_json; // Srd info
    sgx_thread_mutex_t srd_info_mutex = SGX_THREAD_MUTEX_INITIALIZER;
    bool upgrade = false; // True indicates workreport should contain previous public key
    enc_upgrade_status_t upgrade_status = ENC_UPGRADE_STATUS_NONE; // Initial value indicates no upgrade
    json::JSON wl_spec_info; // For workload statistics
    sgx_thread_mutex_t wl_spec_info_mutex = SGX_THREAD_MUTEX_INITIALIZER;
};

#endif /* !_CRUST_WORKLOAD_H_ */
