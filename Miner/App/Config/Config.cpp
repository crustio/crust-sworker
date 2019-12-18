#include "Config.h"

Config *config = NULL;

Config *new_config(const char *path)
{
    if (config != NULL)
    {
        delete config;
    }

    config = new Config(path);
    return config;
}

Config *get_config()
{
    if (config == NULL)
    {
        printf("Please use new_config(path) frist.\n");
        exit(-1);
    }

    return config;
}

Config::Config(std::string path)
{
    // read config
    std::ifstream config_ifs(path);
    std::string config_str((std::istreambuf_iterator<char>(config_ifs)), std::istreambuf_iterator<char>());
    web::json::value config_value = web::json::value::parse(config_str);

    this->empty_path  = config_value["emptyPath"].as_string();
    this->ipfs_api_base_url = config_value["ipfsApiBaseUrl"].as_string();
    this->api_base_url = config_value["apiBaseUrl"].as_string();
    this->api_base_post_url = config_value["apiBasePostUrl"].as_string();
    this->empty_capacity = (size_t)config_value["emptyCapacity"].as_integer();

    this->spid = config_value["spid"].as_string();
    this->linkable = config_value["linkable"].as_integer();
    this->random_nonce = config_value["random_nonce"].as_integer();
    this->use_platform_services = config_value["use_platform_services"].as_integer();
    this->ias_primary_subscription_key = config_value["ias_primary_subscription_key"].as_string();
    this->ias_secondary_subscription_key = config_value["ias_secondary_subscription_key"].as_string();
    this->entry_base_url = config_value["entry_base_url"].as_string();
    this->ias_base_url = config_value["ias_base_url"].as_string();
    this->ias_base_path = config_value["ias_base_path"].as_string();
    this->flags = config_value["flags"].as_integer();
    this->verbose = config_value["verbose"].as_integer();
    this->timeout = config_value["timeout"].as_integer();
    this->tryout = config_value["tryout"].as_integer();

    printf("success\n");
}

void Config::show()
{
    printf("Config:\n{\n");
    printf("    'empty path' : '%s',\n", this->empty_path.c_str());
    printf("    'empty capacity' : %lu,\n", this->empty_capacity);
    printf("    'ipfs api base url' : '%s',\n", this->ipfs_api_base_url.c_str());
    printf("}\n");
}
