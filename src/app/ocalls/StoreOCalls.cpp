#include "StoreOCalls.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: ocall for creating directory
 * @param path (in) -> the path of directory
 * @param type -> Storage type
 * @return: Creating status
 */
crust_status_t ocall_create_dir(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    return create_directory(r_path);
}

/**
 * @description: ocall for renaming directory
 * @param old_path (in) -> the old path of directory
 * @param new_path (in) -> the new path of directory
 * @param type -> File storage type
 * @return: Renaming result status
 */
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path, store_type_t type)
{
    std::string r_old_path = get_real_path_by_type(old_path, type);
    std::string r_new_path = get_real_path_by_type(new_path, type);

    return rename_dir(r_old_path, r_new_path);
}

/**
 * @description: ocall for saving data into file
 * @param path (in) -> file path for saving
 * @param data (in) -> data for saving
 * @param data_size -> the length of data
 * @param type -> Storage type
 * @return: Saving result status
 */
crust_status_t ocall_save_file(const char *path, const uint8_t *data, size_t data_size, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    return save_file(r_path.c_str(), data, data_size);
}

/**
 * @description: Save IPFS file block
 * @param path -> Pointer to block path
 * @param data -> Pointer to block data
 * @param data_size -> Block data size
 * @param uuid -> Buffer used to store uuid
 * @param uuid_len -> UUID length
 * @return: Save result
 */
crust_status_t ocall_save_ipfs_block(const char *path, const uint8_t *data, size_t data_size, char *uuid, size_t /*uuid_len*/)
{
    json::JSON disk_json = get_disk_info();
    if (disk_json.JSONType() != json::JSON::Class::Array || disk_json.size() <= 0)
    {
        return CRUST_UNEXPECTED_ERROR;
    }

    // Choose disk
    std::string cid(path, CID_LENGTH);
    uint32_t start_index = 0;
    read_rand(reinterpret_cast<uint8_t *>(&start_index), sizeof(start_index));
    start_index = start_index % FILE_DISK_LIMIT;
    uint32_t end_index = (CID_LENGTH - 2) / 2;
    uint32_t ci = start_index;  // Current index
    uint32_t oi = ci;           // Origin index
    uint32_t loop_num = FILE_DISK_LIMIT;
    const char *p_index_path = path + 2;
    do
    {
        uint32_t ii = ci * 2;
        uint32_t di = (p_index_path[ii] + p_index_path[ii+1]) % disk_json.size();
        size_t reserved = disk_json[di][WL_DISK_AVAILABLE].ToInt() * 1024 * 1024 * 1024;
        if (reserved > data_size)
        {
            std::string disk_path = disk_json[di][WL_DISK_PATH].ToString();
            std::string uuid_str = EnclaveData::get_instance()->get_uuid(disk_path);
            if (uuid_str.size() == UUID_LENGTH * 2)
            {
                memcpy(uuid, uuid_str.c_str(), uuid_str.size());
                std::string tmp_path = uuid_str + path;
                std::string file_path = get_real_path_by_type(tmp_path.c_str(), STORE_TYPE_FILE);
                if (CRUST_SUCCESS == save_file_ex(file_path.c_str(), data, data_size, mode_t(0664), SF_CREATE_DIR))
                {
                    return CRUST_SUCCESS;
                }
            }
        }
        ci = (ci + 1) % loop_num;
        if (ci == oi)
        {
            ci = FILE_DISK_LIMIT;
            loop_num = end_index + 1;
        }
    } while (ci < end_index);

    return CRUST_STORAGE_NO_ENOUGH_SPACE;
}

/**
 * @description: Delete folder or file
 * @param path (in) -> To be deleted path
 * @param type -> Storage type
 * @return: Saving result status
 */
crust_status_t ocall_delete_folder_or_file(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    if (access(r_path.c_str(), 0) != -1 && rm(r_path.c_str()) == -1)
    {
        p_log->err("Delete '%s' error!\n", r_path.c_str());
        return CRUST_DELETE_FILE_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Delete ipfs block file by cid
 * @param cid -> File root cid
 * @return: Delete result
 */
crust_status_t ocall_delete_ipfs_file(const char *cid)
{
    json::JSON disk_json = get_disk_info();
    if (disk_json.JSONType() != json::JSON::Class::Array || disk_json.size() <= 0)
    {
        p_log->err("Cannot find disk information! Please check your disk!\n");
        return CRUST_UNEXPECTED_ERROR;
    }

    for (int i = 0; i < disk_json.size(); i++)
    {
        std::string path = disk_json[i][WL_DISK_UUID].ToString() + cid;
        path = get_real_path_by_type(path.c_str(), STORE_TYPE_FILE);
        rm_dir(path);
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path (in) -> the path of file
 * @param p_file (out) -> Pointer to pointer file data
 * @param len (out) -> the length of data
 * @param type -> Storage type
 * @return file data
 */
crust_status_t ocall_get_file(const char *path, unsigned char **p_file, size_t *len, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    return get_file(r_path.c_str(), p_file, len);
}

/**
 * @description: Set srd information
 * @param data -> Pointer to srd info data
 * @param data_size -> Srd info data size
 */
void ocall_set_srd_info(const uint8_t *data, size_t data_size)
{
    EnclaveData::get_instance()->set_srd_info(data, data_size);
}
