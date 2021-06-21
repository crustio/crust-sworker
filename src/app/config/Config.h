#ifndef _CRUST_CONFIG_H_
#define _CRUST_CONFIG_H_

#include <stdio.h>
#include <string>
#include <fstream>
#include <omp.h>
#include <set>

#include <sgx_urts.h>

#include "Resource.h"
#include "../enclave/utils/Json.h"
#include "../enclave/utils/Defer.h"
#include "Common.h"
#include "Srd.h"

// ----- IAS CONFIG ----- //
#define IAS_LINKABLE false
#define IAS_RANDOM_NONCE true
#define IAS_BASE_URL  "https://api.trustedservices.intel.com"
#if SGX_DEBUG_FLAG == 1
#define IAS_SPID "138D059F6C7587BAFFFA0961FFB38002"
#define IAS_PRIMARY_SUBSCRIPTION_KEY "1217773e5a82410f98ee70aa1700f599"
#define IAS_SECONDARY_SUBSCRIPTION_KEY "9fdebd5027cd4a57a1eb23d818e7b2e7"
#define IAS_REPORT_PATH  "/sgx/dev/attestation/v3/report"
#else
#define IAS_SPID "668D353F661978655C9D6820CF93B66B"
#define IAS_PRIMARY_SUBSCRIPTION_KEY "80a0aa3b45124b8c8ba937ff9180a226"
#define IAS_SECONDARY_SUBSCRIPTION_KEY "d9df4c30d1db412c9cff3823e30ebb80"
#define IAS_REPORT_PATH  "/sgx/attestation/v3/report"
#endif
#define IAS_FLAGS 0
#define IAS_API_DEF_VERSION 3

class Config
{
public:
    // base information
    std::string base_path;              /* sworker base path */
    std::string db_path;                /* DB path */
    std::string base_url;               /* External API base url */
    
    int websocket_thread_num;           /* WebSocket thread number */
    int srd_thread_num;                 /* srd srd files thread number */

    // crust storage
    std::string ipfs_url;              /* ipfs url */

    // crust chain
    std::string chain_api_base_url; /* Used to connect to Crust API */
    std::string chain_address;      /* The address of crust chain account */
    std::string chain_account_id;   /* The account id(hex string) of crust chain account */
    std::string chain_password;     /* The password of crust chain account */
    std::string chain_backup;       /* The backup of crust chain account */

    void show(void);
    static Config *get_instance();
    std::string get_config_path();
    bool is_valid_or_normal_disk(const std::string &path);
    void refresh_data_paths();
    bool is_valid_data_path(const std::string &path, bool lock = true);
    std::vector<std::string> get_data_paths();
    bool config_file_add_data_paths(const json::JSON &paths);

private:
    static Config *config;
    Config() {}
    Config(const Config &);
    bool unique_paths();
    bool init(std::string path);
    void sort_data_paths();
    Config& operator = (const Config &);
    std::string sys_fsid;
    std::vector<std::string> data_paths;   /* data path */
    std::mutex data_paths_mutex;
    std::vector<std::string> org_data_paths;
    std::mutex org_data_paths_mutex;
};

#endif /* !_CRUST_CONFIG_H_ */
