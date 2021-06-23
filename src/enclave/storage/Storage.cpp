#include "Storage.h"

using namespace std;

crust_status_t check_seal_file_dup(std::string cid);

/**
 * @description: IPFS informs sWorker to seal file
 * @param root -> File root cid
 * @return: Inform result
 */
crust_status_t storage_seal_file_start(const char *root)
{
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string root_cid(root);

    if (ENC_UPGRADE_STATUS_NONE != wl->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    // Check if file number exceeds upper limit
    size_t file_num = 0;
    SafeLock sl_file(wl->file_mutex);
    sl_file.lock();
    file_num += wl->sealed_files.size();
    if (file_num >= FILE_NUMBER_UPPER_LIMIT)
    {
        return CRUST_FILE_NUMBER_EXCEED;
    }

    // Check if file is duplicated
    if (CRUST_SUCCESS != (crust_status = check_seal_file_dup(root_cid.c_str())))
    {
        return crust_status;
    }
    sl_file.unlock();

    // Add file info
    SafeLock sl(wl->pending_files_um_mutex);
    sl.lock();
    if (wl->pending_files_um.size() > FILE_PENDING_LIMIT)
    {
        return CRUST_FILE_NUMBER_EXCEED;
    }
    wl->pending_files_um[root_cid][FILE_BLOCKS][root_cid].AddNum(1);
    sl.unlock();

    // Add info in workload spec
    wl->set_file_spec(FILE_STATUS_PENDING, 1);

    // Store file information
    ocall_store_file_info(root, "{}", FILE_TYPE_PENDING);

    return CRUST_SUCCESS;
}

/**
 * @description: Seal IPFS block
 * @param root -> File root cid
 * @param data -> To be sealed data
 * @param data_size -> To be sealed data size
 * @param is_link -> Indicate data is raw data or a link
 * @param path -> Path in sWorker return to IPFS
 * @param path_size -> Index path size
 * @return: Seal result
 */
crust_status_t storage_seal_file(const char *root,
                                 const uint8_t *data,
                                 size_t data_size,
                                 bool is_link,
                                 char *path,
                                 size_t /*path_size*/)
{
    crust_status_t seal_ret = CRUST_UNEXPECTED_ERROR;
    Workload *wl = Workload::get_instance();
    std::string rcid(root);
    uint8_t *p_plain_data = const_cast<uint8_t *>(data);
    size_t plain_data_sz = data_size;

    Defer defer([&seal_ret, &wl, &rcid, &root](){
        if (CRUST_SUCCESS != seal_ret)
        {
            sgx_thread_mutex_lock(&wl->pending_files_um_mutex);
            wl->pending_files_um.erase(rcid);
            sgx_thread_mutex_unlock(&wl->pending_files_um_mutex);
            // Delete file directory
            crust_status_t del_ret = CRUST_SUCCESS;
            ocall_delete_ipfs_file(&del_ret, root);
            // Delete PENDING status file entry
            SafeLock sl_file(wl->file_mutex);
            sl_file.lock();
            size_t pos = 0;
            if (wl->is_file_dup_nolock(rcid, pos))
            {
                if (FILE_STATUS_PENDING == wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS))
                {
                    wl->sealed_files.erase(wl->sealed_files.begin() + pos);
                    // Delete info in workload spec
                    wl->set_file_spec(FILE_STATUS_PENDING, -1);
                }
            }
            sl_file.unlock();
        }
    });

    if (ENC_UPGRADE_STATUS_NONE != wl->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    // If file transfer completed
    if (p_plain_data == NULL || plain_data_sz == 0)
    {
        return CRUST_STORAGE_UNEXPECTED_FILE_BLOCK;
    }

    // ----- Check file status ----- //
    SafeLock sl_files_info(wl->pending_files_um_mutex);
    sl_files_info.lock();
    if (wl->pending_files_um.find(rcid) == wl->pending_files_um.end()) 
    {
        return CRUST_STORAGE_NEW_FILE_NOTFOUND;
    }

    // ----- Parse file data ----- //
    if (is_link)
    {
        // Unlock files info before dealing with follow complicated computation
        sl_files_info.unlock();

        // Get raw data
        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_sz = 0;
        json::JSON links_json = json::JSON::Load(&seal_ret, p_plain_data, plain_data_sz);
        if (CRUST_SUCCESS != seal_ret)
        {
            return seal_ret;
        }
        if (!(links_json.JSONType() == json::JSON::Class::Object 
                && links_json.hasKey(IPFS_META)
                && links_json[IPFS_META].JSONType() == json::JSON::Class::Array))
        {
            return CRUST_UNEXPECTED_ERROR;
        }
        for (long i = 0; i < links_json.size(); i++)
        {
            std::string s_path = links_json[IPFS_META][i][IPFS_META_PATH].ToString();
            if (CRUST_SUCCESS == (seal_ret = storage_get_file(s_path.c_str(), &p_sealed_data, &sealed_data_sz)))
            {
                break;
            }
        }
        if (CRUST_SUCCESS != seal_ret)
        {
            return seal_ret;
        }
        // Unseal sealed data
        uint8_t *p_decrypted_data = NULL;
        uint32_t decrypted_data_sz = 0;
        if (CRUST_SUCCESS != (seal_ret = unseal_data_mrsigner((sgx_sealed_data_t *)p_sealed_data, sealed_data_sz, &p_decrypted_data, &decrypted_data_sz)))
        {
            return seal_ret;
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
    //log_debug("Dealing with cid '%s'\n", cur_cid.c_str());
    wl->pending_files_um[rcid][FILE_BLOCKS][cur_cid].AddNum(-1);
    sl_files_info.unlock();

    // Push children to map
    std::vector<uint8_t *> children_hashs;
    seal_ret = get_hashs_from_block(p_plain_data, plain_data_sz, children_hashs);
    if (CRUST_SUCCESS != seal_ret)
    {
        return seal_ret;
    }
    sgx_thread_mutex_lock(&wl->pending_files_um_mutex);
    for (size_t i = 0; i < children_hashs.size(); i++)
    {
        std::string ccid = hash_to_cid(reinterpret_cast<const uint8_t *>(children_hashs[i]));
        wl->pending_files_um[rcid][FILE_BLOCKS][ccid].AddNum(1);
        free(children_hashs[i]);
    }
    sgx_thread_mutex_unlock(&wl->pending_files_um_mutex);

    // ----- Seal data ----- //
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_sz = 0;
    seal_ret = seal_data_mrsigner(p_plain_data, plain_data_sz, (sgx_sealed_data_t **)&p_sealed_data, &sealed_data_sz);
    if (CRUST_SUCCESS != seal_ret)
    {
        return seal_ret;
    }
    Defer def_sealed_data([&p_sealed_data](void) { free(p_sealed_data); });
    sgx_sha256_hash_t sealed_hash;
    sgx_sha256_msg(reinterpret_cast<uint8_t *>(p_sealed_data), sealed_data_sz, &sealed_hash);
    std::string sealed_path = std::string(root) + "/" + hexstring_safe(&sealed_hash, HASH_LENGTH);
    // Save sealed block
    char *uuid = (char *)enc_malloc(UUID_LENGTH * 2);
    if (uuid == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    Defer def_uuid([&uuid](void) { free(uuid); });
    memset(uuid, 0, UUID_LENGTH * 2);
    ocall_save_ipfs_block(&seal_ret, sealed_path.c_str(), reinterpret_cast<uint8_t *>(p_sealed_data), sealed_data_sz, uuid, UUID_LENGTH * 2);
    if (CRUST_SUCCESS != seal_ret)
    {
        return seal_ret;
    }
    sealed_path = std::string(uuid, UUID_LENGTH * 2) + sealed_path;
    uint8_t *uuid_u = hex_string_to_bytes(uuid, UUID_LENGTH * 2);
    if (uuid_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    Defer def_uuid_u([&uuid_u](void) { free(uuid_u); });

    // Return index path
    memcpy(path, sealed_path.c_str(), sealed_path.size());

    // Record file info
    sgx_thread_mutex_lock(&wl->pending_files_um_mutex);
    wl->pending_files_um[rcid][FILE_META][FILE_HASH].AppendBuffer(uuid_u, UUID_LENGTH);
    wl->pending_files_um[rcid][FILE_META][FILE_HASH].AppendBuffer(sealed_hash, HASH_LENGTH);
    wl->pending_files_um[rcid][FILE_META][FILE_SIZE].AddNum(plain_data_sz);
    wl->pending_files_um[rcid][FILE_META][FILE_SEALED_SIZE].AddNum(sealed_data_sz);
    wl->pending_files_um[rcid][FILE_META][FILE_BLOCK_NUM].AddNum(1);
    sgx_thread_mutex_unlock(&wl->pending_files_um_mutex);

    seal_ret = CRUST_SUCCESS;

    return seal_ret;
}

/**
 * @description: Seal block end
 * @param root -> File root cid
 * @return: Seal end result
 */
crust_status_t storage_seal_file_end(const char *root)
{
    crust_status_t crust_status = CRUST_UNEXPECTED_ERROR;
    std::string rcid(root);
    Workload *wl = Workload::get_instance();

    Defer defer([&crust_status, &root, &wl](void) {
        if (CRUST_SUCCESS != crust_status)
        {
            // Delete file directory
            crust_status_t del_ret = CRUST_SUCCESS;
            ocall_delete_ipfs_file(&del_ret, root);
        }
        sgx_thread_mutex_lock(&wl->pending_files_um_mutex);
        wl->pending_files_um.erase(root);
        sgx_thread_mutex_unlock(&wl->pending_files_um_mutex);
        // Delete PENDING status file entry
        SafeLock sl(wl->file_mutex);
        sl.lock();
        size_t pos = 0;
        if (wl->is_file_dup_nolock(root, pos))
        {
            if (FILE_STATUS_PENDING == wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS))
            {
                wl->sealed_files.erase(wl->sealed_files.begin() + pos);
                // Delete file info
                ocall_delete_file_info(root, FILE_TYPE_PENDING);
                // Delete info in workload spec
                wl->set_file_spec(FILE_STATUS_PENDING, -1);
            }
        }
        sl.unlock();
    });

    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    // ----- Check if seal complete ----- //
    // Check if file exists
    SafeLock sl(wl->pending_files_um_mutex);
    sl.lock();
    if (wl->pending_files_um.find(rcid) == wl->pending_files_um.end())
    {
        return CRUST_STORAGE_NEW_FILE_NOTFOUND;
    }
    json::JSON file_json = wl->pending_files_um[rcid];
    sl.unlock();
    // Check if getting all blocks
    for (auto m : *(file_json[FILE_BLOCKS].ObjectRange().object))
    {
        if (m.second.ToInt() != 0)
        {
            return CRUST_UNEXPECTED_ERROR;
        }
    }

    std::string cid_str = std::string(root, CID_LENGTH);

    // ----- Add corresponding metadata ----- //
    // Get block height
    size_t chain_block_num = INT_MAX;
    size_t info_buf_sz = strlen(CHAIN_BLOCK_NUMBER) + 3 + HASH_LENGTH
                       + strlen(CHAIN_BLOCK_HASH) + 3 + HASH_LENGTH * 2 + 2
                       + HASH_LENGTH * 2;
    uint8_t *block_info_buf = (uint8_t *)enc_malloc(info_buf_sz);
    if (block_info_buf == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    Defer def_blk_info([&block_info_buf](void) { free(block_info_buf); });
    memset(block_info_buf, 0, info_buf_sz);
    crust_status = safe_ocall_get2(ocall_chain_get_block_info, block_info_buf, &info_buf_sz);
    if (CRUST_SUCCESS == crust_status)
    {
        json::JSON binfo_json = json::JSON::Load_unsafe(block_info_buf, info_buf_sz);
        chain_block_num = binfo_json[CHAIN_BLOCK_NUMBER].ToInt();
    }
    else
    {
        log_warn("Cannot get block information for sealed file.\n");
    }
    // Get file entry info
    json::JSON file_entry_json = file_json[FILE_META];
    sgx_sha256_hash_t sealed_root;
    sgx_sha256_msg(reinterpret_cast<const uint8_t *>(file_entry_json[FILE_HASH].ToBytes()),
            file_entry_json[FILE_HASH].size(), &sealed_root);
    // Store new tree structure
    crust_status = persist_set_unsafe(cid_str, reinterpret_cast<const uint8_t *>(file_entry_json[FILE_HASH].ToBytes()),
            file_entry_json[FILE_HASH].size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    file_entry_json[FILE_CID] = cid_str;
    file_entry_json[FILE_HASH] = (uint8_t *)&sealed_root;
    file_entry_json[FILE_CHAIN_BLOCK_NUM] = chain_block_num;
    // Status indicates current new file's status, which must be one of unverified, valid, lost and deleted
    file_entry_json[FILE_STATUS].AppendChar(FILE_STATUS_VALID).AppendChar(FILE_STATUS_UNVERIFIED).AppendChar(FILE_STATUS_UNVERIFIED);

    // Print sealed file information
    log_info("Seal complete, file info; cid: %s -> size: %ld, status: valid\n",
            file_entry_json[FILE_CID].ToString().c_str(),
            file_entry_json[FILE_SIZE].ToInt());

    // Add new file
    sgx_thread_mutex_lock(&wl->file_mutex);
    size_t pos = 0;
    if (wl->is_file_dup_nolock(root, pos))
    {
        if (FILE_STATUS_DELETED == wl->sealed_files[pos][FILE_STATUS].get_char(CURRENT_STATUS))
        {
            wl->recover_from_deleted_file_buffer(root);
        }
        wl->sealed_files[pos] = file_entry_json;
    }
    else
    {
        wl->add_file_info_nolock(file_entry_json, pos);
    }
    // Delete info in workload spec
    wl->set_file_spec(FILE_STATUS_PENDING, -1);
    sgx_thread_mutex_unlock(&wl->file_mutex);

    // Add info in workload spec
    wl->set_file_spec(FILE_STATUS_VALID, file_entry_json[FILE_SIZE].ToInt());

    // Store file information
    std::string file_info;
    file_info.append("{ \"" FILE_SIZE "\" : ").append(std::to_string(file_entry_json[FILE_SIZE].ToInt())).append(" , ")
        .append("\"" FILE_SEALED_SIZE "\" : ").append(std::to_string(file_entry_json[FILE_SEALED_SIZE].ToInt())).append(" , ")
        .append("\"" FILE_CHAIN_BLOCK_NUM "\" : ").append(std::to_string(chain_block_num)).append(" }");
    ocall_store_file_info(root, file_info.c_str(), FILE_TYPE_VALID);

    crust_status = CRUST_SUCCESS;

    return crust_status;
}

/**
 * @description: Unseal file according to given path
 * @param path -> Pointer to file block stored path
 * @param p_decrypted_data -> Pointer to decrypted data buffer
 * @param decrypted_data_size -> Decrypted data buffer size
 * @param p_decrypted_data_size -> Pointer to decrypted data real size
 * @return: Unseal status
 */
crust_status_t storage_unseal_file(const char *path,
                                   uint8_t *p_decrypted_data,
                                   size_t /*decrypted_data_size*/,
                                   size_t *p_decrypted_data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    uint8_t *p_unsealed_data = NULL;
    uint32_t unsealed_data_sz = 0;

    // Get sealed file block data
    uint8_t *p_data = NULL;
    size_t data_size = 0;
    if (CRUST_SUCCESS != (crust_status = storage_get_file(path, &p_data, &data_size)))
    {
        return crust_status;
    }
    Defer defer_data([&p_data](void) { free(p_data); });
    
    // Do unseal
    if (CRUST_SUCCESS != (crust_status = unseal_data_mrsigner((sgx_sealed_data_t *)p_data, data_size, &p_unsealed_data, &unsealed_data_sz)))
    {
        return crust_status;
    }
    Defer def_decrypted_data([&p_unsealed_data](void) { free(p_unsealed_data); });

    // Check if data is private data
    if (memcmp(p_unsealed_data, SWORKER_PRIVATE_TAG, strlen(SWORKER_PRIVATE_TAG)) == 0)
    {
        return CRUST_MALWARE_DATA_BLOCK;
    }

    // Store unsealed data
    *p_decrypted_data_size = unsealed_data_sz;
    memcpy(p_decrypted_data, p_unsealed_data, *p_decrypted_data_size);

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
    if (wl->is_file_dup_nolock(cid, pos))
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
        crust_status_t del_ret = CRUST_SUCCESS;
        // Delete all about file
        ocall_ipfs_del_all(&del_ret, del_cid.c_str());
        // Update workload spec info
        wl->set_file_spec(deleted_file[FILE_STATUS].get_char(CURRENT_STATUS), -deleted_file[FILE_SIZE].ToInt());
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
 * @description: Check if to be sealed file is duplicated, must hold file_mutex before invoking this function
 * @param cid -> IPFS content id
 * @return: Can seal file or not
 */
crust_status_t check_seal_file_dup(std::string cid)
{
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    size_t pos = 0;
    if (wl->is_file_dup_nolock(cid, pos))
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
        file_entry_json[FILE_STATUS].AppendChar(FILE_STATUS_PENDING).AppendChar(FILE_STATUS_UNVERIFIED).AppendChar(FILE_STATUS_UNVERIFIED);
        wl->add_file_info_nolock(file_entry_json, pos);
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

        // Get link size
        uint32_t link_size = 0;
        for(uint8_t shift = 0;;shift += 7)
        {
            if(shift >= 64)
            {
                return CRUST_UNEXPECTED_ERROR;
            }

            if(index >= block_size)
            {
                return CRUST_UNEXPECTED_ERROR;
            }

            uint8_t b = block_data[index];
            index++;
            link_size |= uint32_t(b&0x7F) << shift;
            if(b < 0x80)
            {
                break;
            }
        }
        
        uint8_t* hash = (uint8_t *)enc_malloc(HASH_LENGTH);
        if (hash == NULL)
        {
            for (size_t i = 0; i < hashs.size(); i++)
            {
                free(hashs[i]);
            }
            hashs.clear();
            return CRUST_MALLOC_FAILED;
        }

        memcpy(hash, block_data + index + 4, HASH_LENGTH);
        hashs.push_back(hash);

        index += link_size;
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
