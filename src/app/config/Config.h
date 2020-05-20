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
    std::string empty_path;             /* Empty validation files base path */
    std::string db_path;                /* DB path */
    size_t empty_capacity;              /* Hard drive storage space for empty validation files, The unit is GB */
    std::string api_base_url;           /* External API base url */
    std::string karst_url;              /* karst websocket url */
    std::string websocket_url;          /* WebSocket url */
    int websocket_thread_num;           /* WebSocket thread number */
    std::string validator_api_base_url; /* Validator base API base url */
    int srd_thread_num;                 /* srd empty files thread number */

    // crust storage
    std::string ipfs_api_base_url; /* Used to connect to IPFS */

    // crust chain
    std::string chain_api_base_url; /* Used to connect to Crust API */
    std::string chain_address;      /* The address of crust chain account */
    std::string chain_account_id;   /* The account id(hex string) of crust chain account */
    std::string chain_password;     /* The password of crust chain account */
    std::string chain_backup;       /* The backup of crust chain account */

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

    static Config *config;

    void show(void);
    void change_empty_capacity(int change);
    static Config *get_instance();

private:
    Config(std::string path);
    Config(const Config &);
    Config& operator = (const Config &);
};

#endif /* !_CRUST_CONFIG_H_ */
