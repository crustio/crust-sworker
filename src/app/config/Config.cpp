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
        if (config_file_path.size() == 0)
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

    // Base configurations
    this->base_path = config_value["base_path"].ToString();
    this->empty_path = this->base_path + "/empty_path";
    this->db_path = this->base_path + "/db";
    this->empty_capacity = config_value["empty_capacity"].ToInt() < 0 ? 0 : (size_t)config_value["empty_capacity"].ToInt();
    this->api_base_url = config_value["api_base_url"].ToString();
  
    this->websocket_url = config_value["websocket_url"].ToString();
    this->websocket_thread_num = config_value["websocket_thread_num"].ToInt();
    this->validator_api_base_url = config_value["validator_api_base_url"].ToString();
    this->srd_thread_num = std::min(omp_get_num_procs(), 6);

    // storage configurations
    this->karst_url = config_value["karst_url"].ToString();

    // crust chain configurations
    this->chain_api_base_url = config_value["chain_api_base_url"].ToString();
    this->chain_address = config_value["chain_address"].ToString();
    this->chain_account_id = config_value["chain_account_id"].ToString();
    if (this->chain_account_id.find("0x") != this->chain_account_id.npos)
    {
        this->chain_account_id.erase(0, 2);
    }
    this->chain_password = config_value["chain_password"].ToString();
    std::string backup_temp = config_value["chain_backup"].ToString();
    remove_chars_from_string(backup_temp, "\\");
    this->chain_backup = backup_temp;

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
}

/**
 * @description: show configurations
 */
void Config::show(void)
{
    printf("Config:\n{\n");
    printf("    'base path' : '%s',\n", this->base_path.c_str());
    printf("    'empty path' : '%s',\n", this->empty_path.c_str());
    printf("    'db path' : '%s',\n", this->db_path.c_str());
    printf("    'empty capacity' : %lu,\n", this->empty_capacity);

    printf("    'api base url' : '%s',\n", this->api_base_url.c_str());
    printf("    'karst url' : '%s',\n", this->karst_url.c_str());
    printf("    'websocket url' : '%s',\n", this->websocket_url.c_str());
    printf("    'websocket thread number' : '%d',\n", this->websocket_thread_num);
    printf("    'validator api base url' : '%s',\n", this->validator_api_base_url.c_str());

    printf("    'chain api base url' : %s,\n", this->chain_api_base_url.c_str());
    printf("    'chain address' : '%s',\n", this->chain_address.c_str());
    printf("    'chain account id' : '%s',\n", this->chain_account_id.c_str());
    printf("    'chain password' : '%s',\n", this->chain_password.c_str());
    printf("    'chain backup' : '%s',\n", this->chain_backup.c_str());

    printf("    'spid' : '%s',\n", this->spid.c_str());
    printf("    'linkable' : '%s',\n", this->linkable ? "true" : "false");
    printf("    'random nonce' : '%s',\n", this->random_nonce ? "true" : "false");
    printf("    'use platform services' : '%s',\n", this->use_platform_services ? "true" : "false");
    printf("    'IAS Primary subscription key' : '%s',\n", this->ias_primary_subscription_key.c_str());
    printf("    'IAS Secondary subscription key' : '%s',\n", this->ias_secondary_subscription_key.c_str());
    printf("    'IAS base url' : '%s',\n", this->ias_base_url.c_str());
    printf("    'IAS base path' : '%s',\n", this->ias_base_path.c_str());
    printf("    'flags' : '%d'\n", this->flags);
    printf("}\n");
}

/**
 * @description: change empty capacity
 * @param change -> the number of empty capacity changed 
 */
void Config::change_empty_capacity(int change)
{
    // Get now empty_capacity
    if (change >= 0 || (size_t)-change <= this->empty_capacity)
    {
        this->empty_capacity += change;
    }
    else
    {
        this->empty_capacity = 0;
    }
}
