#include "OCalls.h"

crust::Log *p_log = crust::Log::get_instance();

// Used to store ocall file data
uint8_t *ocall_file_data = NULL;
size_t ocall_file_data_len = 0;
// Used to store storage related data
uint8_t *_storage_buffer = NULL;
size_t _storage_buffer_len = 0;
// Buffer used to store sealed data
uint8_t *_sealed_data_buf = NULL;
size_t _sealed_data_size = 0;
// Used to validation websocket client
WebsocketClient *wssclient = NULL;
// Used to temporarily store sealed serialized MerkleTree
tbb::concurrent_unordered_map<std::string, std::string> sealed_tree_map;

extern std::mutex srd_info_mutex;
extern bool offline_chain_mode;

/**
 * @description: ocall for printing string
 * @param str -> string for printing
 */
void ocall_print_info(const char *str)
{
    printf("%s", str);
}

/**
 * @description: ocall for printing string
 * @param str -> string for printing
 */
void ocall_print_debug(const char *str)
{
    if (p_log->get_debug_flag())
    {
        printf("%s", str);
    }
}

/**
 * @description: ocall for log information
 * @param str -> string for printing
 */
void ocall_log_info(const char *str)
{
    p_log->info("[Enclave] %s", str);
}

/**
 * @description: ocall for log warnings
 * @param str -> string for printing
 */
void ocall_log_warn(const char *str)
{
    p_log->warn("[Enclave] %s", str);
}

/**
 * @description: ocall for log errors
 * @param str -> string for printing
 */
void ocall_log_err(const char *str)
{
    p_log->err("[Enclave] %s", str);
}

/**
 * @description: ocall for log debugs
 * @param str -> string for printing
 */
void ocall_log_debug(const char *str)
{
    p_log->debug("[Enclave] %s", str);
}

/**
 * @description: ocall for creating directory
 * @param path -> the path of directory
 */
crust_status_t ocall_create_dir(const char *path)
{
    std::vector<std::string> entries;
    boost::split(entries, path, boost::is_any_of("/"));
    std::string cur_path = "";
    if (path[0] == '/')
    {
        cur_path = "/";
    }

    for (auto entry : entries)
    {
        if (entry.compare("") == 0)
            continue;

        cur_path.append(entry).append("/");
        if (access(cur_path.c_str(), 0) == -1)
        {
            if (mkdir(cur_path.c_str(), S_IRWXU) == -1)
            {
                p_log->err("Create directory:%s failed!\n", cur_path.c_str());
                return CRUST_MKDIR_FAILED;
            }
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for renaming directory
 * @param old_path -> the old path of directory
 * @param new_path -> the new path of directory
 */
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path)
{
    if (access(old_path, 0) == -1)
        return CRUST_RENAME_FILE_FAILED;

    std::vector<std::string> old_path_entry;
    std::vector<std::string> new_path_entry;
    boost::split(old_path_entry, old_path, boost::is_any_of("/"));
    boost::split(new_path_entry, new_path, boost::is_any_of("/"));

    if (old_path_entry.size() != new_path_entry.size())
    {
        p_log->err("entry size no equal!\n");
        return CRUST_RENAME_FILE_FAILED;
    }

    size_t entry_size = old_path_entry.size();
    for (size_t i = 0; i < entry_size; i++)
    {
        if (i == entry_size - 1)
        {
            if (rename(old_path, new_path) == -1)
            {
                p_log->err("Rename file:%s to file:%s failed!\n", old_path, new_path);
                return CRUST_RENAME_FILE_FAILED;
            }
        }
        else if (old_path_entry[i].compare(new_path_entry[i]) != 0)
        {
            p_log->err("entry not equal!\n");
            return CRUST_RENAME_FILE_FAILED;
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for saving data into file
 * @param file_path -> file path for saving
 * @param data -> data for saving
 * @param len -> the length of data
 */
crust_status_t ocall_save_file(const char *file_path, const unsigned char *data, size_t len)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    if (! out)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    try
    {
        out.write(reinterpret_cast<const char *>(data), len);
    }
    catch (std::exception e)
    {
        crust_status = CRUST_WRITE_FILE_FAILED;
        p_log->err("Save file:%s failed! Error: %s\n", file_path, e.what());
    }

    out.close();

    return crust_status;
}

/**
 * @description: ocall for geting folders number under directory
 * @param path -> the path of directory
 * @return the number of folders
 */
size_t ocall_get_folders_number_under_path(const char *path)
{
    if (access(path, 0) != -1)
    {
        return get_folders_under_path(std::string(path)).size();
    }
    else
    {
        return 0;
    }
}

crust_status_t ocall_delete_folder_or_file(const char *path)
{
    if (access(path, 0) != -1 && rm(path) == -1)
    {
        p_log->err("Delete '%s' error!\n", path);
        return CRUST_DELETE_FILE_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path -> the path of file
 * @param len -> the length of data
 * @return file data
 */
crust_status_t ocall_get_file(const char *file_path, unsigned char **p_file, size_t *len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (access(file_path, 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat (file_path, &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(file_path, std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    if (*len > ocall_file_data_len)
    {
        ocall_file_data_len = 1024 * (*len / 1024) + ((*len % 1024) ? 1024 : 0);
        ocall_file_data = (uint8_t*)realloc(ocall_file_data, ocall_file_data_len);
        if (ocall_file_data == NULL)
        {
            in.close();
            return CRUST_MALLOC_FAILED;
        }
    }

    in.read(reinterpret_cast<char *>(ocall_file_data), *len);
    in.close();

    *p_file = ocall_file_data;

    return crust_status;
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path -> the path of file
 * @param len -> the length of data
 * @return file data
 */
crust_status_t ocall_get_storage_file(const char *file_path, unsigned char **p_file, size_t *len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (access(file_path, 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat (file_path, &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(file_path, std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    if (*len > _storage_buffer_len)
    {
        _storage_buffer_len = 1024 * (*len / 1024) + ((*len % 1024) ? 1024 : 0);
        _storage_buffer = (uint8_t*)realloc(_storage_buffer, _storage_buffer_len);
        if (_storage_buffer == NULL)
        {
            in.close();
            return CRUST_MALLOC_FAILED;
        }
    }

    in.read(reinterpret_cast<char *>(_storage_buffer), *len);
    in.close();

    *p_file = _storage_buffer;

    return crust_status;
}

/**
 * @description: Temporarily store sealed MerkleTree structure
 * @param org_root_hash -> Original MerkleTree root hash
 * @param tree_data -> Serialized MerkleTree
 * @param tree_len -> Serialized MerkleTree length 
 */
void ocall_store_sealed_merkletree(const char *org_root_hash, const char *tree_data, size_t tree_len)
{
    std::string org_root_hash_str(org_root_hash);
    sealed_tree_map[org_root_hash_str] = std::string(tree_data, tree_len);
}

/**
 * @description: Replace old file with new file
 * @param old_path -> Old file path
 * @param new_path -> New file path
 * @param data -> New file data
 * @param len -> New file data length
 * @return: Replace status
 */
crust_status_t ocall_replace_file(const char *old_path, const char *new_path, const uint8_t *data, size_t len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    // Save new file
    if (CRUST_SUCCESS != (crust_status = ocall_save_file(new_path, data, len)))
    {
        return crust_status;
    }

    // Delete old file
    if (CRUST_SUCCESS != (crust_status = ocall_delete_folder_or_file(old_path)))
    {
        return crust_status;
    }

    return crust_status;
}

/**
 * @description: ocall for wait
 * @param u microsecond
 */
void ocall_usleep(int u)
{
    usleep(u);
}

/**
 * @description: Free app buffer
 * @param value -> Pointer points to pointer to value
 * @return: Get status
 */
crust_status_t ocall_free_outer_buffer(uint8_t **value)
{
    if(*value != NULL)
    {
        free(*value);
        *value = NULL;
    }
    
    return CRUST_SUCCESS;
}

/**
 * @description: Get sub folders and files in indicated path
 * @param path -> Indicated path
 * @param files -> Indicate sub folders and files vector
 * @param files_num -> Sub folders and files number
 */
void ocall_get_sub_folders_and_files(const char *path, char ***files, size_t *files_num)
{
    std::vector<std::string> dirs = get_sub_folders_and_files(path);
    std::vector<const char *> dirs_r;
    for (auto dir : dirs)
    {
        dirs_r.push_back(dir.c_str());
    }

    *files = const_cast<char**>(dirs_r.data());
    *files_num = dirs_r.size();
}

/**
 * @description: Initialize websocket client
 * @return: Initialize status
 */
crust_status_t ocall_validate_init()
{
    if (wssclient != NULL)
        delete wssclient;

    wssclient = new WebsocketClient();
    Config *p_config = Config::get_instance();
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->karst_url);
    if (! wssclient->websocket_init(urlendpoint->ip, std::to_string(urlendpoint->port), urlendpoint->base))
    {
        return CRUST_VALIDATE_INIT_WSS_FAILED;
    }

    // Send backup to server
    std::string res;
    json::JSON backup_json;
    backup_json["backup"] = p_config->chain_backup;
    backup_json["password"] = p_config->chain_password;
    if (! wssclient->websocket_request(backup_json.dump(), res))
    {
        p_log->err("Validate meaningful failed! Send backup to server failed! Error: %s\n", res.c_str());
        return CRUST_VALIDATE_KARST_OFFLINE;
    }
    json::JSON res_json = json::JSON::Load(res);
    if (res_json["status"].ToInt() != 200)
    {
        p_log->err("Validate failed! Karst response: %s\n", res.c_str());
        return CRUST_VALIDATE_WSS_REQUEST_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Get validation files
 * @param root_hash -> File tree root hash
 * @param leaf_hash -> File tree leaf hash
 * @param p_sealed_data -> Pointer to sealed data
 * @param sealed_data_size -> Sealed data size
 * @return: Get validation files status
 */
// TODO: malloc a const space for p_sealed_data
crust_status_t ocall_validate_get_file(const char *root_hash, const char *leaf_hash,
        uint8_t **p_sealed_data, size_t *sealed_data_size)
{
    std::string leaf_hash_str(leaf_hash);
    size_t spos = leaf_hash_str.find("_");
    if (spos == leaf_hash_str.npos)
    {
        p_log->err("Invalid merkletree leaf hash!\n");
        return CRUST_INVALID_MERKLETREE;
    }
    int node_index = atoi(leaf_hash_str.substr(0, spos).c_str());
    std::string leaf_hash_r = leaf_hash_str.substr(spos + 1, leaf_hash_str.size());

    json::JSON req_json;
    req_json["file_hash"] = std::string(root_hash);
    req_json["node_hash"] = leaf_hash_r;
    req_json["node_index"] = node_index;
    std::string res;
    if (! wssclient->websocket_request(req_json.dump(), res))
    {
        p_log->err("Validate meaningful failed! Send request to server failed! Error: %s\n", res.c_str());
        return CRUST_VALIDATE_WSS_REQUEST_FAILED;
    }
    size_t data_size = res.size();
    if (data_size > _sealed_data_size)
    {
        _sealed_data_buf = (uint8_t*)realloc(_sealed_data_buf, data_size);
        if (_sealed_data_buf == NULL)
        {
            p_log->err("Validate: malloc buffer failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        _sealed_data_size = data_size;
    }
    memset(_sealed_data_buf, 0, _sealed_data_size);
    memcpy(_sealed_data_buf, res.c_str(), data_size);
    *p_sealed_data = _sealed_data_buf;
    *sealed_data_size = data_size;

    return CRUST_SUCCESS;
}

/**
 * @description: Close websocket connection
 */
void ocall_validate_close()
{
    if (wssclient != NULL)
    {
        wssclient->websocket_close();
        delete wssclient;
        wssclient = NULL;
    }

    if (_sealed_data_buf != NULL)
    {
        free(_sealed_data_buf);
        _sealed_data_buf = NULL;
        _sealed_data_size = 0;
    }
}

/**
 * @description: Get block hash by height
 * @param block_height -> Block height from enclave
 * @param block_hash -> Pointer to got block hash
 * @param hash_size -> Block hash size
 * @return: Get result
 */
crust_status_t ocall_get_block_hash(size_t block_height, char *block_hash, size_t hash_size)
{
    std::string hash = crust::Chain::get_instance()->get_block_hash(block_height);

    if (hash.compare("") == 0)
    {
        return CRUST_UPGRADE_GET_BLOCK_HASH_FAILED;
    }

    memcpy(block_hash, hash.c_str(), hash_size);

    return CRUST_SUCCESS;
}

/**
 * @description: For upgrade, send work report
 * @param work_report -> Work report
 * @return: Send result
 */
crust_status_t ocall_upload_workreport(const char *work_report)
{
    std::string work_str(work_report);
    remove_char(work_str, '\\');
    remove_char(work_str, '\n');
    remove_char(work_str, ' ');
    p_log->info("Sending work report:%s\n", work_str.c_str());
    if (!offline_chain_mode)
    {
        if (!crust::Chain::get_instance()->post_sworker_work_report(work_str))
        {
            p_log->err("Send work report to crust chain failed!\n");
            return CRUST_UPGRADE_SEND_WORKREPORT_FAILED;
        }
    }

    p_log->info("Send work report to crust chain successfully!\n");

    return CRUST_SUCCESS;
}

/**
 * @description: Entry network
 * @return: Entry result
 */
crust_status_t ocall_entry_network()
{
    return entry_network();
}

/**
 * @description: Lock srd info
 */
void ocall_srd_info_lock()
{
    srd_info_mutex.lock();
}

/**
 * @description: Unlock srd info
 */
void ocall_srd_info_unlock()
{
    srd_info_mutex.unlock();
}

/**
 * @description: Do srd in this function
 * @param change -> The change number will be committed this turn
 */
void ocall_srd_change(long change)
{
    srd_change(change);
}

/**
 * @description: Store sworker identity
 * @param id -> Pointer to identity
 * @return: Upload result
 */
crust_status_t ocall_upload_identity(const char *id)
{
    json::JSON id_json = json::JSON::Load(std::string(id));
    id_json["account_id"] = Config::get_instance()->chain_address;
    std::string sworker_identity = id_json.dump();
    p_log->info("Generate identity successfully! Sworker identity: %s\n", sworker_identity.c_str());

    // Send identity to crust chain
    if (!crust::Chain::get_instance()->wait_for_running())
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    if (!crust::Chain::get_instance()->post_sworker_identity(sworker_identity))
    {
        p_log->err("Send identity to crust chain failed!\n");
        return CRUST_UNEXPECTED_ERROR;
    }
    p_log->info("Send identity to crust chain successfully!\n");

    return CRUST_SUCCESS;
}

/**
 * @description: Store enclave id information
 * @param info -> Pointer to enclave id information
 */
void ocall_store_enclave_id_info(const char *info)
{
    EnclaveData::get_instance()->set_enclave_id_info(info);
}

/**
 * @description: Store enclave workload
 * @param data -> Workload information
 * @param data_size -> Workload size
 */
void ocall_store_workload(const char *data, size_t data_size, bool cover /*=true*/)
{
    if (cover)
    {
        EnclaveData::get_instance()->set_enclave_workload(std::string(data, data_size));
    }
    else
    {
        std::string str = EnclaveData::get_instance()->get_enclave_workload();
        str.append(data, data_size);
        EnclaveData::get_instance()->set_enclave_workload(str);
    }
}

/**
 * @description: Store upgrade data
 * @param data -> Upgrade data
 * */
void ocall_store_upgrade_data(const char *data, size_t data_size, bool cover)
{
    if (cover)
    {
        EnclaveData::get_instance()->set_upgrade_data(std::string(data, data_size));
    }
    else
    {
        std::string str = EnclaveData::get_instance()->get_upgrade_data();
        str.append(data, data_size);
        EnclaveData::get_instance()->set_upgrade_data(str);
    }
}
