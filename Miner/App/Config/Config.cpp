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
    this->empty_capacity = (size_t)config_value["emptyCapacity"].as_integer();
}

void Config::show()
{
    printf("Config:\n{\n");
    printf("    'empty path' : '%s',\n", this->empty_path.c_str());
    printf("    'empty capacity' : %lu,\n", this->empty_capacity);
    printf("    'ipfs api base url' : '%s',\n", this->ipfs_api_base_url.c_str());
    printf("}\n");
}
