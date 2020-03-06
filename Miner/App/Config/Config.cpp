#include "Config.h"

using namespace std;

Config *Config::config = NULL;
std::string config_file_path;

/**
 * @desination: Single instance class function to get instance
 * @return: Configure instance
 * */
Config *Config::get_instance()
{
    if (Config::config == NULL)
    {
        if(config_file_path.size() == 0)
        {
            Config::config = new Config(CONFIG_FILE_PATH);
        }
        else
        {
            Config::config = new Config(config_file_path);
        }
    }

    return Config::config;
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
    json::JSON config_value = json::JSON::Load(config_str);

    // Plot configurations
    this->base_path = config_value["base_path"].ToString();
    this->recover_file_path = this->base_path + "/recover.bin";
    this->empty_path = this->base_path + "/empty_path";
    this->empty_capacity = (size_t)config_value["empty_capacity"].ToInt();

    // ipfs and validator url configurations
    this->ipfs_api_base_url = config_value["ipfs_api_base_url"].ToString();
    this->api_base_url = config_value["api_base_url"].ToString();
    this->validator_api_base_url = config_value["validator_api_base_url"].ToString();

    // crust chain configurations
    this->crust_api_base_url = config_value["crust_api_base_url"].ToString();
    this->crust_address = config_value["crust_address"].ToString();
    this->crust_account_id = config_value["crust_account_id"].ToString();
    this->crust_password = config_value["crust_password"].ToString();
    std::string backup_temp = config_value["crust_backup"].ToString();
    remove_chars_from_string(backup_temp, "\\");
    this->crust_backup = backup_temp;

    // tee identity validation configurations
    this->spid = config_value["spid"].ToString();
    this->linkable = config_value["linkable"].ToBool();
    this->random_nonce = config_value["random_nonce"].ToBool();
    this->use_platform_services = config_value["use_platform_services"].ToBool();
    this->ias_primary_subscription_key = config_value["ias_primary_subscription_key"].ToString();
    this->ias_secondary_subscription_key = config_value["ias_secondary_subscription_key"].ToString();
    this->ias_base_url = config_value["ias_base_url"].ToString();
    this->ias_base_path = config_value["ias_base_path"].ToString();

    this->flags = config_value["flags"].ToInt();
    this->verbose = config_value["verbose"].ToBool();
    this->debug = config_value["debug"].ToBool();
}

/**
 * @description: show configurations
 */
void Config::show(void)
{
    printf("Config:\n{\n");
    printf("    'base path' : '%s',\n", this->base_path.c_str());
    printf("    'recover file path' : '%s',\n", this->recover_file_path.c_str());
    printf("    'empty path' : '%s',\n", this->empty_path.c_str());
    printf("    'empty capacity' : %lu,\n", this->empty_capacity);

    printf("    'ipfs api base url' : '%s',\n", this->ipfs_api_base_url.c_str());
    printf("    'api base url' : '%s',\n", this->api_base_url.c_str());
    printf("    'validator api base url' : '%s',\n", this->validator_api_base_url.c_str());

    printf("    'crust api base url' : %s,\n", this->crust_api_base_url.c_str());
    printf("    'crust address' : '%s',\n", this->crust_address.c_str());
    printf("    'crust account id' : '%s',\n", this->crust_account_id.c_str());
    printf("    'crust password' : '%s',\n", this->crust_password.c_str());
    printf("    'crust backup' : '%s',\n", this->crust_backup.c_str());

    printf("    'spid' : '%s',\n", this->spid.c_str());
    printf("    'linkable' : '%s',\n", this->linkable ? "true" : "false");
    printf("    'random nonce' : '%s',\n", this->random_nonce ? "true" : "false");
    printf("    'use platform services' : '%s',\n", this->use_platform_services ? "true" : "false");
    printf("    'IAS Primary subscription key' : '%s',\n", this->ias_primary_subscription_key.c_str());
    printf("    'IAS Secondary subscription key' : '%s',\n", this->ias_secondary_subscription_key.c_str());
    printf("    'IAS base url' : '%s',\n", this->ias_base_url.c_str());
    printf("    'IAS base path' : '%s',\n", this->ias_base_path.c_str());

    printf("    'flags' : '%d',\n", this->flags);
    printf("    'verbose info' : '%s',\n", this->verbose ? "true" : "false");
    printf("    'debug info' : '%s',\n", this->debug ? "true" : "false");
    printf("}\n");
}
