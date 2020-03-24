#ifndef _CRUST_CONFIG_H_
#define _CRUST_CONFIG_H_

#include <stdio.h>
#include <string>
#include <fstream>
#include <omp.h>
#include "Resource.h"
#include "Json.hpp"
#include "Common.h"

#define IAS_API_DEF_VERSION 3

class Config
{
public:
    // base information
    std::string base_path;              /* TEE base path */
    std::string recover_file_path;      /* Recover file path */
    std::string empty_path;             /* Empty validation files base path */
    size_t empty_capacity;              /* Hard drive storage space for empty validation files, The unit is GB */
    std::string api_base_url;           /* External API base url */
    std::string validator_api_base_url; /* Validator base API base url */
    int plot_thread_num;                /* plot empty files thread number */

    // crust storage
    std::string ipfs_api_base_url; /* Used to connect to IPFS */

    // crust chain
    std::string crust_api_base_url; /* Used to connect to Crust API */
    std::string crust_address;      /* The address of crust chain account */
    std::string crust_account_id;   /* The account id(hex string) of crust chain account */
    std::string crust_password;     /* The password of crust chain account */
    std::string crust_backup;       /* The backup of crust chain account */

    // entry network related
    std::string spid;
    bool linkable;
    bool random_nonce;
    bool use_platform_services;
    std::string ias_primary_subscription_key;
    std::string ias_secondary_subscription_key;
    std::string ias_base_url;

    std::string ias_base_path;
    uint32_t flags;
    // debug related
    bool debug;
    bool verbose;

    static Config *config;

    void show(void);
    static Config *get_instance();

private:
    Config(std::string path);
};

#endif /* !_CRUST_CONFIG_H_ */
