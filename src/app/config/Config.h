#ifndef _CRUST_CONFIG_H_
#define _CRUST_CONFIG_H_

#include <stdio.h>
#include <string>
#include <fstream>
#include <omp.h>
#include "Resource.h"
#include "Json.hpp"
#include "Common.h"

// ----- IAS CONFIG ----- //
#define IAS_SPID "FEF23C7E73A379823CE71FF289CFBC07"
#define IAS_LINKABLE true
#define IAS_RANDOM_NONCE true
#define IAS_PRIMARY_SUBSCRIPTION_KEY "e2e08166ca0f41ef88af2797f007c7cd"
#define IAS_SECONDARY_SUBSCRIPTION_KEY "2ecdd9cb7a004f3e8e0e45ed2ebd1fb4"
#define IAS_BASE_URL  "https://api.trustedservices.intel.com"
#define IAS_REPORT_PATH  "/sgx/dev/attestation/v3/report"
#define IAS_FLAGS 4

#define IAS_API_DEF_VERSION 3

class Config
{
public:
    // base information
    std::string base_path;              /* TEE base path */
    json::JSON srd_paths;               /* Srd paths */
    std::string srd_path;               /* srd validation files base path */
    std::string db_path;                /* DB path */
    size_t srd_capacity;                /* Hard drive storage space for srd validation files, The unit is GB */
    std::string base_url;               /* External API base url */
    
    int websocket_thread_num;           /* WebSocket thread number */
    int srd_thread_num;                 /* srd srd files thread number */

    // crust storage
    std::string karst_url;              /* karst websocket url */

    // crust chain
    std::string chain_api_base_url; /* Used to connect to Crust API */
    std::string chain_address;      /* The address of crust chain account */
    std::string chain_account_id;   /* The account id(hex string) of crust chain account */
    std::string chain_password;     /* The password of crust chain account */
    std::string chain_backup;       /* The backup of crust chain account */

    static Config *config;

    void show(void);
    void change_srd_capacity(int change);
    static Config *get_instance();
    std::string get_config_path();

private:
    Config(std::string path);
    Config(const Config &);
    Config& operator = (const Config &);
};

#endif /* !_CRUST_CONFIG_H_ */
