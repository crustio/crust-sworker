#include "Storage.h"

using namespace std;

// TODO: clear the buffer when timeout
std::unordered_map<std::string, json::JSON> g_files_info_um;
std::unordered_map<std::string, uint32_t> g_files_failed_to_um;
sgx_thread_mutex_t g_files_info_um_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_files_failed_to_um_mutex = SGX_THREAD_MUTEX_INITIALIZER;

crust_status_t _storage_seal_file_end(const char *cid);

crust_status_t check_seal_file_dup(std::string cid);

/**
 * @description: Seal IPFS block
 * @param root -> File root cid
 * @param data -> To be sealed data
 * @param data_size -> To be sealed data size
 * @param sk -> Seal session key
 * @param is_link -> Indicate data is raw data or a link
 * @param path -> Path in sWorker return to IPFS
 * @return: Seal result
 */
crust_status_t storage_seal_file(const char *root,
                                 const uint8_t *data,
                                 size_t data_size,
                                 uint32_t sk,
                                 bool is_link,
                                 char *path,
                                 size_t /*path_size*/)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    std::string rcid(root);
    uint8_t *p_plain_data = const_cast<uint8_t *>(data);
    size_t plain_data_sz = data_size;

    Defer defer([&crust_status, &wl, &rcid, &root, &sk](){
        if (CRUST_SUCCESS != crust_status)
        {
            sgx_thread_mutex_lock(&g_files_info_um_mutex);
            g_files_info_um.erase(rcid);
            g_files_info_um[rcid][FILE_SESSION_KEY] = sk;
            g_files_info_um[rcid][FILE_SEAL_STATUS] = false;
            sgx_thread_mutex_unlock(&g_files_info_um_mutex);
            // Add file failed time out
            sgx_thread_mutex_lock(&g_files_failed_to_um_mutex);
            g_files_failed_to_um[rcid] = 0;
            sgx_thread_mutex_unlock(&g_files_failed_to_um_mutex);
            // Delete file directory
            ocall_delete_folder_or_file(&crust_status, root, STORE_TYPE_FILE_TEMP);
            // Delete PENDING status file entry
            SafeLock sl_file(wl->file_mutex);
            sl_file.lock();
            size_t pos = 0;
            if (wl->is_file_dup(rcid, pos))
            {
                if (FILE_STATUS_PENDING == wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS))
                {
                    wl->sealed_files.erase(wl->sealed_files.begin() + pos);
                }
            }
            sl_file.unlock();
            wl->decrease_file_sealing_count();
        }
    });

    // If file transfer completed
    if (p_plain_data == NULL || plain_data_sz == 0)
    {
        return _storage_seal_file_end(root);
    }

    // Check seal status
    SafeLock sl_files_info(g_files_info_um_mutex);
    sl_files_info.lock();
    bool is_new = false;
    if (g_files_info_um.find(rcid) == g_files_info_um.end()) 
    {
        is_new = true;
    }
    else if (g_files_info_um[rcid][FILE_SESSION_KEY].ToInt() != sk)
    {
        if (!g_files_info_um[rcid][FILE_SEAL_STATUS].ToBool())
        {
            g_files_info_um.erase(rcid);
            is_new = true;
        }
        else
        {
            return CRUST_STORAGE_FILE_DUP;
        }
    }
    else
    {
        if (!g_files_info_um[rcid][FILE_SEAL_STATUS].ToBool())
        {
            return CRUST_SEAL_DATA_FAILED;
        }
    }
    if (is_new)
    {
        // ----- Check if file number exceeds upper limit ----- //
        size_t file_num = 0;
        SafeLock sl_file(wl->file_mutex);
        sl_file.lock();
        file_num += wl->sealed_files.size();
        if (file_num >= FILE_NUMBER_UPPER_LIMIT)
        {
            return crust_status = CRUST_FILE_NUMBER_EXCEED;
        }
        // Check if file is duplicated
        if (CRUST_SUCCESS != (crust_status = check_seal_file_dup(root)))
        {
            return crust_status;
        }
        sl_file.unlock();

        // Create directory
        ocall_create_dir(&crust_status, root, STORE_TYPE_FILE_TEMP);
        if (CRUST_SUCCESS != crust_status)
        {
            return crust_status;
        }

        // Used to optimize to check if current data is the root one
        g_files_info_um[rcid][FILE_BLOCKS][rcid].AddNum(1);
        g_files_info_um[rcid][FILE_SESSION_KEY] = sk;
        g_files_info_um[rcid][FILE_SEAL_STATUS] = true;

        wl->increase_file_sealing_count();
    }
    if (is_link)
    {
        // Unlock files info before dealing with follow complicated computation
        sl_files_info.unlock();

        // ----- Seal block for current file ----- //
        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_sz = 0;
        json::JSON links_json = json::JSON::Load(p_plain_data, plain_data_sz);
        if (!(links_json.JSONType() == json::JSON::Class::Object 
                && links_json.hasKey(IPFS_META)
                && links_json[IPFS_META].JSONType() == json::JSON::Class::Array))
        {
            return CRUST_UNEXPECTED_ERROR;
        }
        for (long i = 0; i < links_json.size(); i++)
        {
            std::string s_path = links_json[IPFS_META][i][IPFS_META_PATH].ToString();
            if (CRUST_SUCCESS == (crust_status = storage_get_file(s_path.c_str(), &p_sealed_data, &sealed_data_sz)))
            {
                break;
            }
        }
        if (CRUST_SUCCESS != crust_status)
        {
            return crust_status;
        }
        // Unseal sealed data
        uint8_t *p_decrypted_data = NULL;
        uint32_t decrypted_data_sz = 0;
        if (CRUST_SUCCESS != (crust_status = unseal_data_mrsigner((sgx_sealed_data_t *)p_sealed_data, sealed_data_sz, &p_decrypted_data, &decrypted_data_sz)))
        {
            return crust_status;
        }
        p_plain_data = p_decrypted_data;
        plain_data_sz = decrypted_data_sz;

        sl_files_info.lock();
    }
    Defer def_plain_data([&p_plain_data, &is_link](void) {
        if (is_link)
        {
            free(p_plain_data);
        }
    });
    sgx_sha256_hash_t cur_hash;
    sgx_sha256_msg(p_plain_data, plain_data_sz, &cur_hash);
    std::string cur_cid = hash_to_cid(reinterpret_cast<const uint8_t *>(&cur_hash));
    log_info("Dealing with cid '%s'\n", cur_cid.c_str());
    g_files_info_um[rcid][FILE_BLOCKS][cur_cid].AddNum(-1);
    sl_files_info.unlock();

    // Push children to map
    std::vector<uint8_t *> children_hashs;
    crust_status = get_hashs_from_block(p_plain_data, plain_data_sz, children_hashs);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    sgx_thread_mutex_lock(&g_files_info_um_mutex);
    for (size_t i = 0; i < children_hashs.size(); i++)
    {
        std::string ccid = hash_to_cid(reinterpret_cast<const uint8_t *>(children_hashs[i]));
        g_files_info_um[rcid][FILE_BLOCKS][ccid].AddNum(1);
        free(children_hashs[i]);
    }
    sgx_thread_mutex_unlock(&g_files_info_um_mutex);

    // ----- Seal data ----- //
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_sz = 0;
    crust_status = seal_data_mrsigner(p_plain_data, plain_data_sz, (sgx_sealed_data_t **)&p_sealed_data, &sealed_data_sz);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    Defer def_sealed_data([&p_sealed_data](void) { free(p_sealed_data); });
    sgx_sha256_hash_t sealed_hash;
    sgx_sha256_msg(reinterpret_cast<uint8_t *>(p_sealed_data), sealed_data_sz, &sealed_hash);
    std::string sealed_path = std::string(root) + "/" + hexstring_safe(&sealed_hash, HASH_LENGTH);
    // Save sealed block
    ocall_save_file(&crust_status, sealed_path.c_str(), reinterpret_cast<uint8_t *>(p_sealed_data), sealed_data_sz, STORE_TYPE_FILE_TEMP);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Return index path
    memcpy(path, sealed_path.c_str(), sealed_path.size());

    // Record file info
    sgx_thread_mutex_lock(&g_files_info_um_mutex);
    g_files_info_um[rcid][FILE_META][FILE_HASH].AppendStr(reinterpret_cast<const char *>(&sealed_hash), HASH_LENGTH);
    g_files_info_um[rcid][FILE_META][FILE_SIZE].AddNum(plain_data_sz);
    g_files_info_um[rcid][FILE_META][FILE_SEALED_SIZE].AddNum(sealed_data_sz);
    g_files_info_um[rcid][FILE_META][FILE_BLOCK_NUM].AddNum(1);
    sgx_thread_mutex_unlock(&g_files_info_um_mutex);

    return crust_status;
}

/**
 * @description: Seal block end
 * @param cid -> File root cid
 * @return: Seal end result
 */
crust_status_t _storage_seal_file_end(const char *cid)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string rcid(cid);
    Workload *wl = Workload::get_instance();

    Defer defer([&crust_status, &rcid, &cid, &wl](void) {
        if (CRUST_SUCCESS != crust_status)
        {
            // Delete file directory
            ocall_delete_folder_or_file(&crust_status, cid, STORE_TYPE_FILE_TEMP);
        }
        sgx_thread_mutex_lock(&g_files_info_um_mutex);
        g_files_info_um.erase(rcid);
        sgx_thread_mutex_unlock(&g_files_info_um_mutex);
        // Delete PENDING status file entry
        SafeLock sl(wl->file_mutex);
        sl.lock();
        size_t pos = 0;
        if (wl->is_file_dup(cid, pos))
        {
            if (FILE_STATUS_PENDING == wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS))
            {
                wl->sealed_files.erase(wl->sealed_files.begin() + pos);
            }
        }
        sl.unlock();
        wl->decrease_file_sealing_count();
    });

    // Check if seal complete
    SafeLock sl(g_files_info_um_mutex);
    sl.lock();
    if (g_files_info_um.find(rcid) == g_files_info_um.end())
    {
        return crust_status = CRUST_STORAGE_NEW_FILE_NOTFOUND;
    }
    for (auto m : *(g_files_info_um[rcid][FILE_BLOCKS].ObjectRange().object))
    {
        if (m.second.ToInt() != 0)
        {
            return crust_status = CRUST_UNEXPECTED_ERROR;
        }
    }
    sl.unlock();

    ocall_rename_dir(&crust_status, cid, cid, STORE_TYPE_FILE_TEMP, STORE_TYPE_FILE);
    if (CRUST_SUCCESS != crust_status)
    {
        ocall_delete_folder_or_file(&crust_status, cid, STORE_TYPE_FILE_TEMP);
        return crust_status;
    }

    sgx_thread_mutex_lock(&wl->file_sealing_count_mutex);
    if (wl->file_sealing_count == 1)
    {
        ocall_delete_folder_or_file(&crust_status, "", STORE_TYPE_FILE_TEMP);
    }
    sgx_thread_mutex_unlock(&wl->file_sealing_count_mutex);

    std::string cid_str = std::string(cid, CID_LENGTH);

    // ----- Add corresponding metadata ----- //
    // Get block height
    size_t chain_block_num = INT_MAX;
    size_t info_buf_sz = strlen(CHAIN_BLOCK_NUMBER) + 3 + HASH_LENGTH
                         + strlen(CHAIN_BLOCK_HASH) + 3 + HASH_LENGTH * 2 + 2
                         + HASH_LENGTH * 2;
    char *block_info_buf = (char *)enc_malloc(info_buf_sz);
    if (block_info_buf == NULL)
    {
        return crust_status = CRUST_MALLOC_FAILED;
    }
    Defer def_blk_info([&block_info_buf](void) { free(block_info_buf); });
    memset(block_info_buf, 0, info_buf_sz);
    ocall_chain_get_block_info(&crust_status, block_info_buf, info_buf_sz);
    if (CRUST_SUCCESS == crust_status)
    {
        json::JSON binfo_json = json::JSON::Load(std::string(block_info_buf));
        chain_block_num = binfo_json[CHAIN_BLOCK_NUMBER].ToInt();
    }
    else
    {
        log_warn("Cannot get block information for sealed file.\n");
    }
    // Get file entry info
    sgx_thread_mutex_lock(&g_files_info_um_mutex);
    json::JSON file_entry_json = g_files_info_um[rcid][FILE_META];
    sgx_thread_mutex_unlock(&g_files_info_um_mutex);
    sgx_sha256_hash_t sealed_root;
    sgx_sha256_msg(reinterpret_cast<const uint8_t *>(file_entry_json[FILE_HASH].ToCStr()),
            file_entry_json[FILE_HASH].size(), &sealed_root);
    // Store new tree structure
    crust_status = persist_set_unsafe(cid_str, reinterpret_cast<const uint8_t *>(file_entry_json[FILE_HASH].ToCStr()),
            file_entry_json[FILE_HASH].size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    file_entry_json[FILE_CID] = cid_str;
    file_entry_json[FILE_HASH] = (uint8_t *)&sealed_root;
    file_entry_json[FILE_CHAIN_BLOCK_NUM] = chain_block_num;
    // Status indicates current new file's status, which must be one of valid, unverified and deleted
    file_entry_json[FILE_STATUS] = "100";

    // Print sealed file information
    log_info("Seal complete, file info; cid: %s -> size: %ld, status: valid\n",
            file_entry_json[FILE_CID].ToString().c_str(),
            file_entry_json[FILE_SIZE].ToInt());

    // Add new file
    sgx_thread_mutex_lock(&wl->file_mutex);
    size_t pos = 0;
    if (wl->is_file_dup(cid, pos))
    {
        if (FILE_STATUS_DELETED == wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS))
        {
            wl->recover_from_deleted_file_buffer(cid);
        }
        wl->sealed_files[pos] = file_entry_json;
    }
    else
    {
        wl->add_sealed_file(file_entry_json, pos);
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    // Add info in workload spec
    wl->set_wl_spec(FILE_STATUS_VALID, file_entry_json[FILE_SIZE].ToInt());

    // Store file information
    std::string file_info;
    file_info.append("{ \\\"" FILE_SIZE "\\\" : ").append(std::to_string(file_entry_json[FILE_SIZE].ToInt())).append(" , ")
        .append("\\\"" FILE_SEALED_SIZE "\\\" : ").append(std::to_string(file_entry_json[FILE_SEALED_SIZE].ToInt())).append(" , ")
        .append("\\\"" FILE_CHAIN_BLOCK_NUM "\\\" : ").append(std::to_string(chain_block_num)).append(" }");
    ocall_store_file_info(cid, file_info.c_str());

    return CRUST_SUCCESS;
}

/**
 * @description: Unseal file according to given path
 * @param path -> Pointer to file block stored path
 * @return: Unseal status
 */
crust_status_t storage_unseal_file(const char *path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    uint8_t *p_decrypted_data = NULL;
    uint32_t decrypted_data_sz = 0;

    // Get sealed file block data
    uint8_t *p_data = NULL;
    size_t data_size = 0;
    if (CRUST_SUCCESS != storage_get_file(path, &p_data, &data_size))
    {
        return CRUST_STORAGE_FILE_BLOCK_NOTFOUND;
    }
    Defer defer_data([&p_data](void) { free(p_data); });
    
    // Do unseal
    if (CRUST_SUCCESS != (crust_status = unseal_data_mrsigner((sgx_sealed_data_t *)p_data, data_size, &p_decrypted_data, &decrypted_data_sz)))
    {
        return crust_status;
    }

    // Check if data is private data
    if (memcmp(p_decrypted_data, SWORKER_PRIVATE_TAG, strlen(SWORKER_PRIVATE_TAG)) == 0)
    {
        return CRUST_MALWARE_DATA_BLOCK;
    }

    // Store unsealed data
    ocall_store_unsealed_data(path, p_decrypted_data, decrypted_data_sz);

    return crust_status;
}

/**
 * @description: Delete meaningful file
 * @param cid -> File root cid
 * @return: Delete status
 */
crust_status_t storage_delete_file(const char *cid)
{
    // ----- Delete file items in metadata ----- //
    json::JSON deleted_file;
    crust_status_t crust_status = CRUST_SUCCESS;

    // ----- Delete file items in sealed_files ----- //
    Workload *wl = Workload::get_instance();
    SafeLock sf_lock(wl->file_mutex);
    sf_lock.lock();
    size_t pos = 0;
    if (wl->is_file_dup(cid, pos))
    {
        if (wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
        {
            log_info("File(%s) has been deleted!\n", cid);
            return CRUST_SUCCESS;
        }
        deleted_file = wl->sealed_files[pos];
        wl->add_to_deleted_file_buffer(cid);
        wl->sealed_files[pos][FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
    }
    sf_lock.unlock();

    if (deleted_file.size() > 0)
    {
        // ----- Delete file related data ----- //
        std::string del_cid = deleted_file[FILE_CID].ToString();
        // Delete file tree structure
        persist_del(del_cid);
        // Update workload spec info
        wl->set_wl_spec(deleted_file[FILE_STATUS].get_char(CURRENT_STATUS), -deleted_file[FILE_SIZE].ToInt());
        log_info("Delete file:%s successfully!\n", cid);
    }
    else
    {
        log_warn("Delete file:%s failed(not found)!\n", cid);
        crust_status = CRUST_STORAGE_NEW_FILE_NOTFOUND;
    }

    return crust_status;
}

/**
 * @description: Delete failed file info
 */
void del_failed_file_info()
{
    // Increase deleted files timeout
    sgx_thread_mutex_lock(&g_files_failed_to_um_mutex);
    std::vector<std::string> del_cids_v;
    for (auto it = g_files_failed_to_um.begin(); it != g_files_failed_to_um.end(); )
    {
        it->second++;
        if (it->second > FILE_DELETE_TIMEOUT)
        {
            del_cids_v.push_back(it->first);
            it = g_files_failed_to_um.erase(it);
        }
        else
        {
            it++;
        }
    }
    sgx_thread_mutex_unlock(&g_files_failed_to_um_mutex);

    // Delete file info by deleted cid
    if (del_cids_v.size() > 0)
    {
        sgx_thread_mutex_lock(&g_files_info_um_mutex);
        for (auto cid : del_cids_v)
        {
            if (g_files_info_um.find(cid) != g_files_info_um.end() && 
                    !g_files_info_um[cid][FILE_SEAL_STATUS].ToBool())
            {
                g_files_info_um.erase(cid);
            }
        }
        sgx_thread_mutex_unlock(&g_files_info_um_mutex);
    }
}

/**
 * @description: Check if to be sealed file is duplicated, must hold file_mutex before invoking this function
 * @param cid -> IPFS content id
 * @return: Can seal file or not
 */
crust_status_t check_seal_file_dup(std::string cid)
{
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    size_t pos = 0;
    if (wl->is_file_dup(cid, pos))
    {
        crust_status = CRUST_STORAGE_FILE_DUP;
        char cur_s = wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS);
        char org_s = wl->sealed_files[pos][FILE_STATUS].get_char(ORIGIN_STATUS);
        if (FILE_STATUS_PENDING == cur_s)
        {
            crust_status = CRUST_STORAGE_FILE_SEALING;
        }
        else if (FILE_STATUS_DELETED == cur_s)
        {
            if (FILE_STATUS_DELETED == org_s || FILE_STATUS_UNVERIFIED == org_s)
            {
                crust_status = CRUST_SUCCESS;
            }
            else
            {
                // If the original status is valid, we cannot seal the same new file.
                // If do that, increasement report may be crashed due to unknown work report result
                crust_status = CRUST_STORAGE_FILE_DELETING;
                log_info("File(%s) is being deleted, please wait.\n", cid.c_str());
            }
        }
    }

    if (CRUST_SUCCESS == crust_status)
    {
        json::JSON file_entry_json;
        file_entry_json[FILE_CID] = cid;
        // Set file status to 'FILE_STATUS_PENDING,FILE_STATUS_UNVERIFIED,FILE_STATUS_UNVERIFIED'
        file_entry_json[FILE_STATUS] = "300";
        wl->add_sealed_file(file_entry_json, pos);
    }

    return crust_status;
}

/**
 * @description: Get the hashs of links from ipfs block
 * @param block_data -> ipfs block data
 * @param block_size -> ipfs block size
 * @param hashs -> Return hashs, which need to be released when used up
 * @return: Status
 */
crust_status_t get_hashs_from_block(const uint8_t *block_data, size_t block_size, std::vector<uint8_t *> &hashs)
{
    if (block_data == NULL || block_size == 0)
    {
        return CRUST_STORAGE_EMPTY_BLOCK;
    }

    size_t index = 0;
    while (index <= block_size)
    {
        if (block_data[index] != 0x12)
        {
            break;
        }
        index++;
        uint8_t link_size = block_data[index];
        
        uint8_t* hash = (uint8_t *)enc_malloc(HASH_LENGTH);
        if (hash == NULL)
        {
            for (size_t i = 0; i < hashs.size(); i++)
            {
                delete hashs[i];
            }
            hashs.clear();
            return CRUST_MALLOC_FAILED;
        }

        memcpy(hash, block_data + index + 5, HASH_LENGTH);
        hashs.push_back(hash);

        index += link_size + 1;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Storage get file data
 * @param path -> File path
 * @param p_data -> Pointer to pointer file data
 * @param data_size -> Pointer to data size
 * @return: Get result
 */
crust_status_t storage_get_file(const char *path, uint8_t **p_data, size_t *data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    ocall_get_file(&crust_status, path, p_data, data_size, STORE_TYPE_FILE);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    uint8_t *p_sealed_data = (uint8_t *)enc_malloc(*data_size);
    if (p_sealed_data == NULL)
    {
        ocall_free_outer_buffer(&crust_status, p_data);
        return CRUST_MALLOC_FAILED;
    }
    memset(p_sealed_data, 0, *data_size);
    memcpy(p_sealed_data, *p_data, *data_size);

    ocall_free_outer_buffer(&crust_status, p_data);

    *p_data = p_sealed_data;

    return crust_status;
}

/**
 * @description: Get ipfs block
 * @param cid -> Ipfs content id
 * @param p_data -> Ipfs data
 * @param data_size -> Pointer to ipfs data size
 * @return: Get status
 */
crust_status_t storage_ipfs_get_block(const char *cid, uint8_t **p_data, size_t *data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_ipfs_get_block(&crust_status, cid, p_data, data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    uint8_t *p_enc_data = (uint8_t *)enc_malloc(*data_size);
    if (p_enc_data == NULL)
    {
        ocall_free_outer_buffer(&crust_status, p_data);
        return CRUST_MALLOC_FAILED;
    }
    memset(p_enc_data, 0, *data_size);
    memcpy(p_enc_data, *p_data, *data_size);

    ocall_free_outer_buffer(&crust_status, p_data);

    *p_data = p_enc_data;

    return crust_status;
}

/**
 * @description: Ipfs cat data by content id
 * @param cid -> Ipfs content id
 * @param p_data -> Ipfs data
 * @param data_size -> Pointer to ipfs data size
 * @return: Cat status
 */
crust_status_t storage_ipfs_cat(const char *cid, uint8_t **p_data, size_t *data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_ipfs_cat(&crust_status, cid, p_data, data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    uint8_t *p_enc_data = (uint8_t *)enc_malloc(*data_size);
    if (p_enc_data == NULL)
    {
        ocall_free_outer_buffer(&crust_status, p_data);
        return CRUST_MALLOC_FAILED;
    }
    memset(p_enc_data, 0, *data_size);
    memcpy(p_enc_data, *p_data, *data_size);

    ocall_free_outer_buffer(&crust_status, p_data);

    *p_data = p_enc_data;

    return crust_status;
}
