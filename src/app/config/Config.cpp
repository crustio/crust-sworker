#include "Config.h"

using namespace std;

Config *Config::config = NULL;
std::mutex config_mutex;
crust::Log *p_log = crust::Log::get_instance();
std::string config_file_path = CRUST_INST_DIR "/etc/Config.json";

/**
 * @desination: Single instance class function to get instance
 * @return: Configure instance
 */
Config *Config::get_instance()
{
    SafeLock sl(config_mutex);
    sl.lock();
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
    crust_status_t crust_status = CRUST_SUCCESS;

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
        p_log->err("'base path' cannot be empty! Please configure 'base_path'!\n");
        return false;
    }
    this->db_path = this->base_path + "/db";
    if (CRUST_SUCCESS != (crust_status = create_directory(this->db_path)))
    {
        p_log->err("Create path:'%s' failed! Error code:%lx\n", this->db_path.c_str(), crust_status);
        return false;
    }

    // Set data path
    json::JSON data_paths = config_value["data_path"];
    if (data_paths.JSONType() != json::JSON::Class::Array
            || data_paths.size() < 0)
    {
        p_log->err("Please configure 'data_path'!\n");
        return false;
    }
    for (int i = 0; i < data_paths.size(); i++)
    {
        std::string d_path = data_paths[i].ToString();
        this->org_data_paths.push_back(d_path);
        if (CRUST_SUCCESS != (crust_status = create_directory(d_path)))
        {
            p_log->err("Create path:'%s' failed! Error code:%lx\n", d_path.c_str(), crust_status);
            return false;
        }
    }
    if (! this->unique_paths())
    {
        p_log->warn("No valid data path is configured!\n");
    }

    // Set base url
    this->base_url = config_value["base_url"].ToString();
    if (this->base_url.compare("") == 0)
    {
        p_log->err("Please configure 'base_url'!\n");
        return false;
    }
  
    // Set srd related
    this->srd_thread_num = std::min(omp_get_num_procs() * 2, SRD_THREAD_NUM);

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
    printf("    'data path' : [\n");
    std::vector<std::string> d_paths = this->get_data_paths();
    for (auto it = d_paths.begin(); it != d_paths.end(); )
    {
        printf("        \"%s\"", (*it).c_str());
        ++it == d_paths.end() ? printf("\n") : printf(",\n");
    }
    printf("    ],\n");
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
 * @description: Unique data paths
 * @return: Has valid data path or not
 */
bool Config::unique_paths()
{
    // Get system disk fsid
    struct statfs sys_st;
    if (statfs(this->base_path.c_str(), &sys_st) != -1)
    {
        this->sys_fsid = hexstring_safe(&sys_st.f_fsid, sizeof(sys_st.f_fsid));
    }

    this->refresh_data_paths();

    return 0 != this->data_paths.size();
}

/**
 * @description: Sort data paths
 */
void Config::sort_data_paths()
{
    this->data_paths_mutex.lock();
    std::sort(this->data_paths.begin(), this->data_paths.end(), [](std::string s1, std::string s2) {
        if (s1.length() != s2.length())
        {
            return s1.size() < s2.size();
        }
        return s1.compare(s2) < 0;
    });
    this->data_paths_mutex.unlock();
}

/**
 * @description: Check if given path is in the system disk
 * @param path -> Const reference to given path
 * @return: System disk or not
 */
bool Config::is_valid_or_normal_disk(const std::string &path)
{
    struct statfs st;
    if (statfs(path.c_str(), &st) == -1)
    {
        return false;
    }

    data_paths_mutex.lock();
    size_t data_paths_size = this->data_paths.size();
    data_paths_mutex.unlock();

    std::string fsid = hexstring_safe(&st.f_fsid, sizeof(st.f_fsid));

    return this->sys_fsid.compare(fsid) != 0 || data_paths_size == 1;
}

/**
 * @description: Refresh data paths
 */
void Config::refresh_data_paths()
{
    this->org_data_paths_mutex.lock();
    std::set<std::string> org_data_paths(this->org_data_paths.begin(), this->org_data_paths.end());
    this->org_data_paths_mutex.unlock();

    std::vector<std::string> data_paths;
    std::set<std::string> sids_s;
    std::string sys_disk_path;
    for (auto path : org_data_paths)
    {
        struct statfs st;
        if (statfs(path.c_str(), &st) != -1)
        {
            std::string fsid = hexstring_safe(&st.f_fsid, sizeof(st.f_fsid));
            // Compare to check if current disk is system disk
            if (this->sys_fsid.compare(fsid) != 0)
            {
                // Remove duplicated disk
                if (sids_s.find(fsid) == sids_s.end())
                {
                    data_paths.push_back(path);
                    sids_s.insert(fsid);
                }
            }
            else
            {
                if (sys_disk_path.size() == 0)
                {
                    sys_disk_path = path;
                }
            }
        }
    }

    // If no valid data path and system disk is configured, choose sys disk
    if (data_paths.size() == 0 && sys_disk_path.size() != 0)
    {
        data_paths.push_back(sys_disk_path);
    }
    this->data_paths_mutex.lock();
    this->data_paths = data_paths;
    this->data_paths_mutex.unlock();


    // Sort data paths
    this->sort_data_paths();
}

/**
 * @description: Get data paths
 * @return: Data paths
 */
std::vector<std::string> Config::get_data_paths()
{
    SafeLock sl(this->data_paths_mutex);
    sl.lock();
    return this->data_paths;
}

/**
 * @description: Check if given data path is valid
 * @param path -> Reference to given data path
 * @param lock -> Get data paths lock or not
 * @return: Valid or not
 */
bool Config::is_valid_data_path(const std::string &path, bool lock)
{
    std::map<std::string, std::string> sid_2_path;
    if (lock)
    {
        this->data_paths_mutex.lock();
    }
    for (auto p : this->data_paths)
    {
        struct statfs st;
        if (statfs(p.c_str(), &st) != -1)
        {
            std::string fsid = hexstring_safe(&st.f_fsid, sizeof(st.f_fsid));
            sid_2_path[fsid] = p;
        }
    }
    if (lock)
    {
        this->data_paths_mutex.unlock();
    }

    struct statfs st;
    if (statfs(path.c_str(), &st) != -1)
    {
        std::string fsid = hexstring_safe(&st.f_fsid, sizeof(st.f_fsid));
        // Check if current disk is system disk
        if (this->sys_fsid.compare(fsid) == 0 )
        {
            return false;
        }
        // Check if added path is duplicated
        if (sid_2_path.find(fsid) == sid_2_path.end())
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    return false;
}

/**
 * @description: Add data paths to config file
 * @param paths -> Const reference to paths
 * @return: Add success or not
 */
bool Config::config_file_add_data_paths(const json::JSON &paths)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    if (paths.JSONType() != json::JSON::Class::Array || paths.size() <= 0)
    {
        p_log->err("Add data path failed, Wrong paths parameter!\n");
        return false;
    }
    else
    {
        uint8_t *p_data = NULL;
        size_t data_size = 0;
        if (CRUST_SUCCESS != (crust_status = get_file(config_file_path.c_str(), &p_data, &data_size)))
        {
            p_log->err("Add data path failed, read config file failed!\n");
            return false;
        }
        else
        {
            json::JSON config_json = json::JSON::Load(p_data, data_size);
            free(p_data);
            if (config_json["data_path"].JSONType() != json::JSON::Class::Array)
            {
                p_log->err("Add data path failed, invalid config file!\n");
                return false;
            }
            SafeLock sl(this->data_paths_mutex);
            sl.lock();
            std::set<std::string> paths_s(this->data_paths.begin(), this->data_paths.end());
            std::vector<std::string> valid_paths;
            bool is_valid = false;
            for (auto path : paths.ArrayRange())
            {
                std::string pstr = path.ToString();
                if (this->is_valid_data_path(pstr, false))
                {
                    config_json["data_path"].append(path);
                    if (paths_s.find(pstr) == paths_s.end())
                    {
                        valid_paths.push_back(pstr);
                        paths_s.insert(pstr);
                        is_valid = true;
                    }
                }
            }
            this->data_paths.insert(this->data_paths.end(), valid_paths.begin(), valid_paths.end());
            sl.unlock();
            // Insert valid paths to org data paths
            this->org_data_paths_mutex.lock();
            this->org_data_paths.insert(this->org_data_paths.end(), valid_paths.begin(), valid_paths.end());
            this->org_data_paths_mutex.unlock();
            if (! is_valid)
            {
                return false;
            }
            this->sort_data_paths();
            std::string config_str = config_json.dump();
            replace(config_str, "\\\\", "\\");
            crust_status = save_file(config_file_path.c_str(), reinterpret_cast<const uint8_t *>(config_str.c_str()), config_str.size());
            if (CRUST_SUCCESS != crust_status)
            {
                p_log->err("Save new config file failed! Error code: %lx\n", crust_status);
                return false;
            }
        }
    }

    return true;
}
