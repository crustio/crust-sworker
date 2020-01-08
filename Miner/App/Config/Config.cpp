#include "Config.h"

Config *config = NULL;

/**
 * @description: new a global config
 * @param path -> configurations file path
 * @return: new config point
 */
Config *new_config(const char *path)
{
    if (config != NULL)
    {
        delete config;
    }

    config = new Config(path);
    return config;
}

/**
 * @description: get the global config
 * @return: config point
 */
Config *get_config(void)
{
    if (config == NULL)
    {
        printf("Please use new_config(path) frist.\n");
        exit(-1);
    }

    return config;
}

/**
 * @description: constructor
 * @param path -> configurations file path 
 */
Config::Config(std::string path)
{
    /* Read user configurations from file */
    std::ifstream config_ifs(path);
    std::string config_str((std::istreambuf_iterator<char>(config_ifs)), std::istreambuf_iterator<char>());

    /* Fill configurations */
    web::json::value config_value = web::json::value::parse(config_str);
    this->empty_path = config_value["emptyPath"].as_string();
    this->ipfs_api_base_url = config_value["ipfsApiBaseUrl"].as_string();
    this->api_base_url = config_value["apiBaseUrl"].as_string();
    this->request_url = config_value["requestUrl"].as_string();
    this->empty_capacity = (size_t)config_value["emptyCapacity"].as_integer();

    this->spid = config_value["spid"].as_string();
    // TODO: true or false, include linkable, random nonce, verbose ...
    this->linkable = config_value["linkable"].as_integer();
    this->random_nonce = config_value["random_nonce"].as_integer();
    this->use_platform_services = config_value["use_platform_services"].as_integer();
    this->ias_primary_subscription_key = config_value["ias_primary_subscription_key"].as_string();
    this->ias_secondary_subscription_key = config_value["ias_secondary_subscription_key"].as_string();
    this->ias_base_url = config_value["ias_base_url"].as_string();
    this->ias_base_path = config_value["ias_base_path"].as_string();

    // TODO: session related
    this->flags = config_value["flags"].as_integer();
    this->verbose = config_value["verbose"].as_integer();
    this->debug = config_value["debug"].as_integer();
}

/**
 * @description: show configurations
 */
void Config::show(void)
{
    printf("Config:\n{\n");
    printf("    'empty path' : '%s',\n", this->empty_path.c_str());
    printf("    'empty capacity' : %lu,\n", this->empty_capacity);
    printf("    'ipfs api base url' : '%s',\n", this->ipfs_api_base_url.c_str());
    printf("    'api base url' : '%s',\n", this->api_base_url.c_str());
    printf("    'request url' : '%s',\n", this->request_url.c_str());
    printf("    'spid' : '%s',\n", this->spid.c_str());
    printf("    'linkable' : '%d',\n", this->linkable);
    printf("    'random nonce' : '%d',\n", this->random_nonce);
    printf("    'use platform services' : '%d',\n", this->use_platform_services);
    printf("    'IAS Primary subscription key' : '%s',\n", this->ias_primary_subscription_key.c_str());
    printf("    'IAS Secondary subscription key' : '%s',\n", this->ias_secondary_subscription_key.c_str());
    printf("    'IAS base url' : '%s',\n", this->ias_base_url.c_str());
    printf("    'IAS base path' : '%s',\n", this->ias_base_path.c_str());
    printf("    'verbose info' : '%d',\n", this->verbose);
    printf("    'debug info' : '%d',\n", this->debug);
    printf("}\n");
}
