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
std::unordered_map<char, std::string> g_file_status = {
    {FILE_STATUS_UNCONFIRMED, "unconfirmed"},
    {FILE_STATUS_VALID, "valid"},
    {FILE_STATUS_LOST, "lost"},
    {FILE_STATUS_DELETED, "deleted"}
};

class Workload
{
public:
    std::map<std::string, std::vector<uint8_t*>> srd_path2hashs_m;         /* used to store all G srd file collection' hashs */

    std::vector<json::JSON> checked_files;
    std::vector<json::JSON> new_files;
    std::vector<std::pair<std::string, size_t>> order_files;
    std::set<size_t> reported_files_idx;
    sgx_ec256_public_t pre_pub_key;
    
    static Workload *workload;
    static Workload *get_instance();
    ~Workload();
    std::string get_workload(void);
    void serialize_srd(std::string &sered_srd);
    crust_status_t serialize_file(uint8_t **p_data, size_t *data_size);
    crust_status_t restore_srd(json::JSON g_hashs);
    void restore_file(json::JSON file_json);
    crust_status_t get_srd_info(sgx_sha256_hash_t *srd_root_out, uint64_t *srd_workload_out, json::JSON &md_json);
    void clean_data();

    void add_new_file(json::JSON file);
    void add_order_file(std::pair<std::string, size_t> file);

    void set_report_flag(bool flag);
    bool get_report_flag();

    void set_srd_info(std::string path, long change);
    json::JSON get_srd_info();
    json::JSON gen_workload_info();

    void set_upgrade(sgx_ec256_public_t pub_key);
    bool is_upgrade();

    void set_upgrade_status(enc_upgrade_status_t status);
    enc_upgrade_status_t get_upgrade_status();

    void handle_report_result();

    // Workreport mutex
    sgx_thread_mutex_t ocall_wr_mutex = SGX_THREAD_MUTEX_INITIALIZER;
    // Workload mutex
    sgx_thread_mutex_t ocall_wl_mutex = SGX_THREAD_MUTEX_INITIALIZER;
    // Upgrade mutex
    sgx_thread_mutex_t ocall_upgrade_mutex = SGX_THREAD_MUTEX_INITIALIZER;

private:
    Workload();
    // True indicates report files this turn, false means not report
    bool report_files;
    // Srd info
    json::JSON srd_info_json;
    // Srd info mutex
    sgx_thread_mutex_t srd_info_mutex = SGX_THREAD_MUTEX_INITIALIZER;
    // Is upgrade
    bool upgrade = false;
    // Upgrade status 
    enc_upgrade_status_t upgrade_status = ENC_UPGRADE_STATUS_NONE;
};

#endif /* !_CRUST_WORKLOAD_H_ */
