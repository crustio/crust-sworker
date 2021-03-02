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
        Config::config = new Config();
        if (!Config::config->init(config_file_path))
        {
            delete Config::config;
            return NULL;
        }
    }

    return Config::config;
}

/**
 * @description: Initialze config
 * @param path -> Configure file path 
 * @return: Initialize result
 */
bool Config::init(std::string path)
{
    /* Read user configurations from file */
    std::ifstream config_ifs(path);
    std::string config_str((std::istreambuf_iterator<char>(config_ifs)), std::istreambuf_iterator<char>());

    // Fill configurations
    json::JSON config_value = json::JSON::Load(config_str);

    crust::Log *p_log = crust::Log::get_instance();
    // Base configurations
    this->base_path = config_value["base_path"].ToString();
    if (this->base_path.compare("") == 0)
    {
        p_log->err("Please configure 'base_path'!\n");
        return false;
    }
    this->db_path = this->base_path + "/db";

    // Set data_path related
    std::string data_path = config_value["data_path"].ToString();
    if (data_path.compare("") == 0)
    {
        p_log->err("Please configure 'data_path'!\n");
        return false;
    }
    this->srd_path = data_path + "/srd";
    this->file_path = data_path + "/file";
    this->temp_srd_path = data_path + "/../sworker_srd_temp";
    this->temp_file_path = data_path + "/../sworker_file_temp";

    // Set base url
    this->base_url = config_value["base_url"].ToString();
    if (this->base_url.compare("") == 0)
    {
        p_log->err("Please configure 'base_url'!\n");
        return false;
    }
  
    // Set srd related
    this->srd_thread_num = std::min(omp_get_num_procs() * 2, SRD_THREAD_MAX_NUM);
    this->srd_ratio = SRD_RATIO_DEFAULT;

    // Set storage configure related
    this->ipfs_url = config_value["ipfs_url"].ToString();
    if (this->ipfs_url.compare("") == 0)
    {
        p_log->err("Please configure 'ipfs_url'!\n");
        return false;
    }

    // ----- Crust chain configure ----- //
    // Base url
    this->chain_api_base_url = config_value["chain"]["base_url"].ToString();
    if (this->chain_api_base_url.compare("") == 0)
    {
        p_log->err("Please configure 'chain base_url'!\n");
        return false;
    }
    // Address
    this->chain_address = config_value["chain"]["address"].ToString();
    if (this->chain_address.compare("") == 0)
    {
        p_log->err("Please configure 'chain address'!\n");
        return false;
    }
    // Account id
    this->chain_account_id = config_value["chain"]["account_id"].ToString();
    if (this->chain_account_id.compare("") == 0)
    {
        p_log->err("Please configure 'chain account_id'!\n");
        return false;
    }
    if (this->chain_account_id.find("0x") != this->chain_account_id.npos)
    {
        this->chain_account_id.erase(0, 2);
    }
    // Password
    this->chain_password = config_value["chain"]["password"].ToString();
    if (this->chain_password.compare("") == 0)
    {
        p_log->err("Please configure 'chain password'!\n");
        return false;
    }
    // Backup
    std::string backup_temp = config_value["chain"]["backup"].ToString();
    remove_chars_from_string(backup_temp, "\\");
    this->chain_backup = backup_temp;
    if (this->chain_backup.compare("") == 0)
    {
        p_log->err("Please configure 'chain backup'!\n");
        return false;
    }

    return true;
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
    //printf("        'spid' : '%s',\n", IAS_SPID);
    //printf("        'linkable' : '%s',\n", IAS_LINKABLE ? "true" : "false");
    //printf("        'random nonce' : '%s',\n", IAS_RANDOM_NONCE ? "true" : "false");
    //printf("        'primary subscription key' : '%s',\n", IAS_PRIMARY_SUBSCRIPTION_KEY);
    //printf("        'secondary subscription key' : '%s',\n", IAS_SECONDARY_SUBSCRIPTION_KEY);
    printf("        'base url' : '%s',\n", IAS_BASE_URL);
    printf("        'report path' : '%s'\n", IAS_REPORT_PATH);
    //printf("        'flags' : '%d'\n", IAS_FLAGS);
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

/**
 * @description: Set srd space to disk space ratio
 * @param ratio -> Srd space to disk total space ratio
 */
void Config::set_srd_ratio(double ratio)
{
    this->srd_ratio_mutex.lock();
    this->srd_ratio = ratio;
    this->srd_ratio_mutex.unlock();
}

/**
 * @description: Get srd ratio
 * @return: Srd ratio
 */
double Config::get_srd_ratio()
{
    this->srd_ratio_mutex.lock();
    double ratio = this->srd_ratio;
    this->srd_ratio_mutex.unlock();

    return ratio;
}
