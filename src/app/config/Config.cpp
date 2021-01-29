#include "Config.h"

using namespace std;

Config *Config::config = NULL;
std::string config_file_path;

/**
 * @desination: Single instance class function to get instance
 * @return: Configure instance
 */
Config *Config::get_instance()
{
    if (Config::config == NULL)
    {
        Config::config = new Config(config_file_path);
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
    this->srd_path = config_value["data_path"].ToString() + "/srd";
    this->file_path = config_value["data_path"].ToString() + "/file";
    this->db_path = this->base_path + "/db";
    this->base_url = config_value["base_url"].ToString();
  
    this->srd_thread_num = std::min(omp_get_num_procs() * 2, SRD_THREAD_MAX_NUM);

    // storage configurations
    this->ipfs_url = config_value["ipfs_url"].ToString();

    // crust chain configurations
    this->chain_api_base_url = config_value["chain"]["base_url"].ToString();
    this->chain_address = config_value["chain"]["address"].ToString();
    this->chain_account_id = config_value["chain"]["account_id"].ToString();
    if (this->chain_account_id.find("0x") != this->chain_account_id.npos)
    {
        this->chain_account_id.erase(0, 2);
    }
    this->chain_password = config_value["chain"]["password"].ToString();
    std::string backup_temp = config_value["chain"]["backup"].ToString();
    remove_chars_from_string(backup_temp, "\\");
    this->chain_backup = backup_temp;
}

/**
 * @description: show configurations
 */
void Config::show(void)
{
    printf("Config : {\n");
    printf("    'base path' : '%s',\n", this->base_path.c_str());
    printf("    'db path' : '%s',\n", this->db_path.c_str());
    printf("    'srd path' : '%s',\n", this->srd_path.c_str());
    printf("    'file path' : '%s',\n", this->file_path.c_str());
    printf("    'base url' : '%s',\n", this->base_url.c_str());
    printf("    'ipfs url' : '%s',\n", this->ipfs_url.c_str());

    printf("    'chain config' : {\n");
    printf("        'base url' : %s,\n", this->chain_api_base_url.c_str());
    printf("        'address' : '%s',\n", this->chain_address.c_str());
    printf("        'account id' : '%s',\n", this->chain_account_id.c_str());
    printf("        'password' : 'xxxxxx',\n");
    printf("        'backup' : 'xxxxxx'\n");
    printf("    },\n");

    printf("    'IAS parameters' : {\n");
    printf("        'spid' : '%s',\n", IAS_SPID);
    printf("        'linkable' : '%s',\n", IAS_LINKABLE ? "true" : "false");
    printf("        'random nonce' : '%s',\n", IAS_RANDOM_NONCE ? "true" : "false");
    printf("        'primary subscription key' : '%s',\n", IAS_PRIMARY_SUBSCRIPTION_KEY);
    printf("        'secondary subscription key' : '%s',\n", IAS_SECONDARY_SUBSCRIPTION_KEY);
    printf("        'base url' : '%s',\n", IAS_BASE_URL);
    printf("        'report path' : '%s',\n", IAS_REPORT_PATH);
    printf("        'flags' : '%d'\n", IAS_FLAGS);
    printf("    }\n");
    printf("}\n");
}

/**
 * @description: Get configure file path
 * @return: Configure file path
 */
std::string Config::get_config_path()
{
    return config_file_path;
}
