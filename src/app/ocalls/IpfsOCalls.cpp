#include "IpfsOCalls.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Test if there is usable IPFS
 * @return: Test result
 */
bool ocall_ipfs_online()
{
    return Ipfs::get_instance()->online();
}

/**
 * @description: Get block from ipfs
 * @param cid (in) -> Ipfs content id
 * @param p_data (out) -> Pointer to pointer to ipfs data
 * @param data_size (out) -> Pointer to ipfs data size
 * @return: Status
 */
crust_status_t ocall_ipfs_get_block(const char *cid, uint8_t **p_data, size_t *data_size)
{
    *data_size = Ipfs::get_instance()->block_get(cid, p_data);
    if (*data_size == 0)
    {
        if (!Ipfs::get_instance()->online())
        {
            return CRUST_SERVICE_UNAVAILABLE;
        }
        return CRUST_STORAGE_IPFS_BLOCK_GET_ERROR;
    }
    return CRUST_SUCCESS;
}

/**
 * @description: Save IPFS file block
 * @param path (in) -> Pointer to block path
 * @param data (in) -> Pointer to block data
 * @param data_size -> Block data size
 * @param uuid (in) -> Buffer used to store uuid
 * @param uuid_len -> UUID length
 * @return: Save result
 */
crust_status_t ocall_save_ipfs_block(const char *path, const size_t cid_len, const uint8_t *data, size_t data_size, char *uuid, size_t /*uuid_len*/)
{
    json::JSON disk_json = get_disk_info();
    std::string path_str(path);
    const int choose_len = 40;
    const int cid_len = path_str.find_last_of('/');
    std::string cid(path, cid_len);

    if (disk_json.JSONType() != json::JSON::Class::Array || disk_json.size() <= 0 || path_str.length() <= choose_len)
    {
        return CRUST_UNEXPECTED_ERROR;
    }

    EnclaveData *ed = EnclaveData::get_instance();

    // Choose a string of length 40
    std::string for_choose = "";
    
    if (cid_len > choose_len)
    {
        for_choose = path_str.substr(cid_len - choose_len, choose_len);
    }
    else
    {
        for_choose = path_str.substr(0, choose_len);
    }
    
    uint32_t start_index = 0;
    read_rand(reinterpret_cast<uint8_t *>(&start_index), sizeof(start_index));
    start_index = start_index % FILE_DISK_LIMIT;
    uint32_t ci = start_index;  // Current index
    
    // Choose disk
    for (size_t i = 0; i < choose_len/FILE_DISK_LIMIT;)
    {
        uint32_t ii = ci + i*FILE_DISK_LIMIT;
        uint32_t di = (for_choose[ii%choose_len] + for_choose[(ii+1)%choose_len] + for_choose[(ii+2)%choose_len] + for_choose[(ii+3)%choose_len]) % disk_json.size();
        
        // Check if there is enough space
        size_t reserved = disk_json[di][WL_DISK_AVAILABLE].ToInt() * 1024 * 1024 * 1024;
        if (reserved > data_size * 4)
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
                    ed->add_pending_file_size(cid, data_size);
                    return CRUST_SUCCESS;
                }
            }
        }

        ci = (ci + 1) % FILE_DISK_LIMIT;
        if (ci == start_index)
        {
            i++;
        }
    }

    return CRUST_STORAGE_NO_ENOUGH_SPACE;
}

/**
 * @description: Cat file
 * @param cid (in) -> Ipfs content id
 * @param p_data (out) -> Pointer to pointer to ipfs data
 * @param data_size (out) -> Pointer to ipfs data size
 * @return: Status
 */
crust_status_t ocall_ipfs_cat(const char *cid, uint8_t **p_data, size_t *data_size)
{
    if (!Ipfs::get_instance()->online())
    {
        return CRUST_SERVICE_UNAVAILABLE;
    }

    *data_size = Ipfs::get_instance()->cat(cid, p_data);
    if (*data_size == 0)
    {
        return CRUST_STORAGE_IPFS_CAT_ERROR;
    }
    return CRUST_SUCCESS;
}

/**
 * @description: Add file to ipfs
 * @param p_data (in) -> Pointer to be added data
 * @param len -> Added data length
 * @param cid (in) -> Pointer to returned ipfs content id
 * @param cid_len -> File content id length
 * @return: Status
 */
crust_status_t ocall_ipfs_add(uint8_t *p_data, size_t len, char *cid, size_t /*cid_len*/)
{
    std::string cid_str = Ipfs::get_instance()->add(p_data, len);
    if (cid_str.size() == 0)
    {
        return CRUST_STORAGE_IPFS_ADD_ERROR;
    }

    memcpy(cid, cid_str.c_str(), cid_str.size());

    return CRUST_SUCCESS;
}

/**
 * @description: Delete ipfs block file by cid
 * @param cid (in) -> File root cid
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
 * @description: Delete file
 * @param cid (in) -> To be deleted file cid
 * @return: Status
 */
crust_status_t ocall_ipfs_del(const char *cid)
{
    if (!Ipfs::get_instance()->del(cid))
    {
        p_log->warn("Invoke IPFS pin rm file(cid:%s) failed! Please check your IPFS.\n", cid);
        return CRUST_UNEXPECTED_ERROR;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Delete file's all related data
 * @param cid (in) -> To be deleted file cid
 * @return: Status
 */
crust_status_t ocall_ipfs_del_all(const char *cid)
{
    // Delete ipfs file
    Ipfs::get_instance()->del(cid);

    // Delete file data
    ocall_delete_ipfs_file(cid);

    // Delete sealed tree
    crust::DataBase::get_instance()->del(cid);

    // Delete statistics information
    EnclaveData::get_instance()->del_file_info(cid);

    return CRUST_SUCCESS;
}
