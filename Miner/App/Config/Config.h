#ifndef _CRUST_CONFIG_H_
#define _CRUST_CONFIG_H_

#include <stdio.h>
#include <string>
#include <fstream>
#include "Resource.h"
#include "json.hpp"

#define IAS_API_DEF_VERSION 3

class Config
{
public:
    std::string empty_path;             /* Empty validation files base path */
    size_t empty_capacity;              /* Hard drive storage space for empty validation files, The unit is GB */
    std::string ipfs_api_base_url;      /* Used to connect to IPFS */
    std::string api_base_url;           /* External API base url */
    std::string validator_api_base_url; /* Validator base API base url */

    // crust chain
    std::string crust_api_base_url; /* Used to connect to Crust API */
    std::string crust_account_id;   /* The password of crust chain account */
    std::string crust_password;     /* The password of crust chain account */
    std::string crust_backup;       /* The backup of crust chain account */

    // entry network related
    std::string spid;
    int linkable;
    int random_nonce;
    int use_platform_services;
    std::string ias_primary_subscription_key;
    std::string ias_secondary_subscription_key;
    std::string ias_base_url;

    std::string ias_base_path;
    uint32_t flags;
    // debug related
    int debug;
    int verbose;

    static Config *config;

    void show(void);
    static Config *get_instance();

private:
    Config(std::string path);
};

#endif /* !_CRUST_CONFIG_H_ */
