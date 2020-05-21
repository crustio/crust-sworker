#include "OCalls.h"
#include "DataBase.h"
#include "FileUtils.h"
#include "Config.h"
#include "BufferPool.h"
#include <exception>

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
// Buffer pool
BufferPool *p_buf_pool = BufferPool::get_instance();
// Used to temporarily store sealed serialized MerkleTree
std::map<std::string, std::string> sealed_tree_map;


/**
 * @description: ocall for printing string
 * @param str -> string for printing
 */
void ocall_print_string(const char *str)
{
    printf("%s", str);
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

    for (size_t i = 0; i < entries.size(); i++)
    {
        cur_path.append("/").append(entries[i]);
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
    if (access(path, 0) == -1 || rm(path) == -1)
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
 * */
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
 * */
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
 * @description: TEE gets file block data by path
 * @param root_hash -> MerkleTree root hash
 * @param cur_hash -> Recieved indicated file block hash
 * @param hash_len -> Hash length
 * @param path -> Vector of path from root to leaf node
 * @param path_count -> Vector size
 * @return: Get status
 * */
crust_status_t ocall_get_file_block_by_path(char * /*root_hash*/, char * /*cur_hash*/, uint32_t /*hash_len*/, uint32_t *path, uint32_t path_count)
{
    std::vector<uint32_t> path_v(path, path + path_count);
    // TODO: Send path to storage and get corresponding file block

    return CRUST_SUCCESS;
}

/**
 * @description: Add record to DB
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Add status
 * */
crust_status_t ocall_persist_add(const char *key, const uint8_t *value, size_t value_len)
{
    return crust::DataBase::get_instance()->add(std::string(key), std::string((const char*)value, value_len));
}

/**
 * @description: Delete record from DB
 * @param key -> Pointer to key
 * @return: Delete status
 * */
crust_status_t ocall_persist_del(const char *key)
{
    return crust::DataBase::get_instance()->del(std::string(key));
}

/**
 * @description: Update record in DB
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Update status
 * */
crust_status_t ocall_persist_set(const char *key, const uint8_t *value, size_t value_len)
{
    return crust::DataBase::get_instance()->set(std::string(key), std::string((const char*)value, value_len));
}

/**
 * @description: Get record from DB
 * @param key -> Pointer to key
 * @param value -> Pointer points to pointer to value
 * @param value_len -> value length
 * @return: Get status
 * */
crust_status_t ocall_persist_get(const char *key, uint8_t **value, size_t *value_len)
{
    std::string val;
    crust_status_t crust_status = crust::DataBase::get_instance()->get(std::string(key), val);
    if (CRUST_SUCCESS != crust_status)
    {
        *value_len = 0;
        return crust_status;
    }
    *value_len = val.size();
    // Get buffer
    uint8_t *p_buffer = p_buf_pool->get_buffer(*value_len);
    memcpy(p_buffer, val.c_str(), *value_len);
    *value = p_buffer;

    return crust_status;
}

/**
 * @description: Get sub folders and files in indicated path
 * @param path -> Indicated path
 * @param files -> Indicate sub folders and files vector
 * @param files_num -> Sub folders and files number
 * */
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
 * */
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
    if (! wssclient->websocket_request(backup_json.dump(), res))
    {
        p_log->err("Validate failed! Send backup to server failed!\n");
        return CRUST_VALIDATE_WSS_REQUEST_FAILED;
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
 * */
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
 * */
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
