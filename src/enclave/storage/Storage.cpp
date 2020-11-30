#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "EJson.h"

using namespace std;

// Lock used to lock outside buffer
sgx_thread_mutex_t g_file_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

// Current node public and private key pair
extern sgx_thread_mutex_t g_sealed_files_mutex;

crust_status_t _storage_seal_file(const char *cid, 
                                  size_t &sealed_size, 
                                  size_t &origin_size, 
                                  size_t &block_num, 
                                  uint8_t *sealed_buffer, 
                                  size_t *sealed_buffer_offset, 
                                  json::JSON &tree);

int check_file_dup(std::string cid);

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param cid -> Pointer to ipfs content id
 * @return: Seal status
 */
crust_status_t storage_seal_file(const char *cid)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Check if file number exceeds upper limit
    size_t file_num = 0;
    sgx_thread_mutex_lock(&g_sealed_files_mutex);
    file_num += wl->sealed_files.size();
    sgx_thread_mutex_unlock(&g_sealed_files_mutex);

    if (file_num >= FILE_NUMBER_UPPER_LIMIT)
    {
        return CRUST_FILE_NUMBER_EXCEED;
    }

    // Check if file is duplicated
    int check_file_res = check_file_dup(cid);
    if (0 == check_file_res)
    {
        return CRUST_STORAGE_FILE_DUP;
    }

    // Do seal file
    size_t sealed_size = 0;
    size_t origin_size = 0;
    size_t block_num = 0;
    json::JSON tree_json;
    crust_status = _storage_seal_file(cid, sealed_size, origin_size, block_num, NULL, NULL, tree_json);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    std::string cid_str = std::string(cid, CID_LENGTH);
    std::string tree_str = tree_json.dump();
    remove_char(tree_str, '\n');
    remove_char(tree_str, '\\');
    remove_char(tree_str, ' ');

    // ----- Add corresponding metadata ----- //
    std::string root_hash = tree_json[MT_HASH].ToString();
    uint8_t *root_hash_u = hex_string_to_bytes(root_hash.c_str(), root_hash.size());
    if (root_hash_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    // Get block height
    size_t chain_block_num = 0;
    size_t info_buf_size = strlen(CHAIN_BLOCK_NUMBER) + 3 + HASH_LENGTH
        + strlen(CHAIN_BLOCK_HASH) + 3 + HASH_LENGTH * 2 + 2
        + HASH_LENGTH * 2;
    char *block_info_buf = (char *)enc_malloc(info_buf_size);
    memset(block_info_buf, 0, info_buf_size);
    ocall_chain_get_block_info(&crust_status, block_info_buf, info_buf_size);
    if (CRUST_SUCCESS != crust_status)
    {
        json::JSON binfo_json = json::JSON::Load(std::string(block_info_buf));
        chain_block_num = binfo_json[CHAIN_BLOCK_NUMBER].ToInt();
    }
    free(block_info_buf);
    json::JSON file_entry_json;
    file_entry_json[FILE_CID] = cid_str;
    file_entry_json[FILE_HASH] = root_hash_u;
    file_entry_json[FILE_SIZE] = origin_size;
    file_entry_json[FILE_SEALED_SIZE] = sealed_size;
    file_entry_json[FILE_BLOCK_NUM] = block_num;
    file_entry_json[FILE_CHAIN_BLOCK_NUM] = chain_block_num;
    // Status indicates current new file's status, which must be one of valid, lost and unverified
    if (2 == check_file_res)
    {
        file_entry_json[FILE_STATUS] = "111";
    }
    else
    {
        file_entry_json[FILE_STATUS] = "100";
    }
    free(root_hash_u);

    // Store new tree structure
    crust_status = persist_set_unsafe(cid_str, reinterpret_cast<const uint8_t *>(tree_str.c_str()), tree_str.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Print sealed file information
    log_info("Seal complete, file info; cid: %s -> size: %ld, status: valid\n",
            file_entry_json[FILE_CID].ToString().c_str(),
            file_entry_json[FILE_SIZE].ToInt());

    // Add new file to buffer
    sgx_thread_mutex_lock(&g_sealed_files_mutex);
    wl->sealed_files.push_back(file_entry_json);
    sgx_thread_mutex_unlock(&g_sealed_files_mutex);

    // Add info in workload spec
    wl->set_wl_spec(FILE_STATUS_VALID, file_entry_json[FILE_SIZE].ToInt());

    // Store file information
    std::string file_info;
    file_info.append("{ \\\"" FILE_SIZE "\\\" : ").append(std::to_string(origin_size)).append(" , ")
        .append("\\\"sealed_size\\\" : ").append(std::to_string(sealed_size)).append(" , ")
        .append("\\\"block_number\\\" : ").append(std::to_string(chain_block_num)).append(" }");
    ocall_store_file_info(cid, file_info.c_str());

    return crust_status;
}

/**
 * @description: Do seal file
 * @param cid -> Const pointer to ipfs content id
 * @param sealed_size -> Sealed file total size
 * @param origin_size -> Origin file total size
 * @param block_num -> Total block number
 * @param sealed_buffer -> Used to collect ipfs data
 * @param sealed_buffer_offset -> Used to indicate stored ipfs data size
 * @param tree -> Reference to current node
 * @return: Seal status
 */
crust_status_t _storage_seal_file(const char *cid,
                                  size_t &sealed_size,
                                  size_t &origin_size, 
                                  size_t &block_num, 
                                  uint8_t *sealed_buffer, 
                                  size_t *sealed_buffer_offset, 
                                  json::JSON &tree)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    bool is_first = false;

    // Frist loop
    if (sealed_buffer == NULL)
    {
        tree[MT_LINKS] = json::Array();
        is_first = true;
        sealed_buffer_offset = (size_t *)enc_malloc(sizeof(size_t));
        *sealed_buffer_offset = 0;
        sealed_buffer = (uint8_t *)enc_malloc(FILE_CAL_BUFFER_SIZE);
        if (sealed_buffer == NULL)
        {
            free(sealed_buffer_offset);
            return CRUST_MALLOC_FAILED;
        }
        memset(sealed_buffer, 0, FILE_CAL_BUFFER_SIZE);
    }

    // Get ipfs block data
    uint8_t *p_block_data = NULL;
    size_t block_size = 0;
    crust_status = storage_ipfs_get_block(cid, &p_block_data, &block_size);
    if (CRUST_SUCCESS != crust_status)
    {
        if (is_first)
        {
            free(sealed_buffer);
            free(sealed_buffer_offset);
        }
        return crust_status;
    }

    // Compare cid
    sgx_sha256_hash_t data_hash;
    sgx_sha256_msg(p_block_data, block_size, &data_hash);
    std::string real_cid = hash_to_cid(reinterpret_cast<const uint8_t *>(&data_hash));
    if (memcmp(cid, real_cid.c_str(), CID_LENGTH) != 0)
    {
        free(p_block_data);
        if (is_first)
        {
            free(sealed_buffer);
            free(sealed_buffer_offset);
        }
        return CRUST_UNEXPECTED_ERROR;
    }

    // ----- If buffer overflow, store data ----- //
    if (*sealed_buffer_offset + block_size >= FILE_CAL_BUFFER_SIZE)
    {
        // Do seal
        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_size = 0;
        crust_status = seal_data_mrsigner(sealed_buffer, *sealed_buffer_offset,
                (sgx_sealed_data_t **)&p_sealed_data, &sealed_data_size);
        // Refresh buffer
        if (CRUST_SUCCESS != crust_status)
        {
            *sealed_buffer_offset = 0;
            free(p_block_data);
            return crust_status;
        }
        sgx_sha256_hash_t sealed_hash;
        sgx_sha256_msg(p_sealed_data, sealed_data_size, &sealed_hash);
        // Add sealed data to ipfs and get related cid
        char n_cid[CID_LENGTH];
        ocall_ipfs_add(&crust_status, p_sealed_data, sealed_data_size, n_cid, CID_LENGTH);
        free(p_sealed_data);
        if (CRUST_SUCCESS != crust_status)
        {
            *sealed_buffer_offset = 0;
            free(p_block_data);
            return crust_status;
        }
        json::JSON sub_tree;
        sub_tree[MT_DATA_HASH] = hexstring_safe(reinterpret_cast<uint8_t *>(&sealed_hash), HASH_LENGTH);
        sub_tree[MT_CID] = std::string(n_cid, CID_LENGTH);
        tree[MT_LINKS].append(sub_tree);
        sealed_size += sealed_data_size;
        origin_size += *sealed_buffer_offset;
        block_num++;
        *sealed_buffer_offset = 0;
    }

    // Copy data to caculate buffer
    memcpy(sealed_buffer + *sealed_buffer_offset, p_block_data, block_size);
    *sealed_buffer_offset += block_size;

    // Deal with children
    std::vector<uint8_t *> children_hashs;
    crust_status = get_hashs_from_block(p_block_data, block_size, children_hashs);
    free(p_block_data);
    if (CRUST_SUCCESS != crust_status)
    {
        if (is_first)
        {
            free(sealed_buffer);
            free(sealed_buffer_offset);
        }
        return crust_status;
    }
    for (size_t i = 0; i < children_hashs.size(); i++)
    {
        std::string child_cid = hash_to_cid(children_hashs[i]);
        crust_status = _storage_seal_file(child_cid.c_str(), sealed_size, origin_size, block_num, sealed_buffer, sealed_buffer_offset, tree);
        if (CRUST_SUCCESS != crust_status)
        {
            log_err("Seal sub data failed!Error code:%lx\n", crust_status);
            for (size_t j = i; j < children_hashs.size(); j++)
            {
                free(children_hashs[j]);
            }
            break;
        }
        free(children_hashs[i]);
    }

    // ----- Will quit from loop ----- //
    if (is_first)
    {
        // Deal with left data
        do
        {
            if (*sealed_buffer_offset <= 0 || CRUST_SUCCESS != crust_status)
            {
                break;
            }
            // Do seal
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            crust_status = seal_data_mrsigner(sealed_buffer, *sealed_buffer_offset,
                    (sgx_sealed_data_t **)&p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                break;
            }
            sgx_sha256_hash_t sealed_hash;
            sgx_sha256_msg(reinterpret_cast<const uint8_t *>(p_sealed_data), sealed_data_size, &sealed_hash);
            // Add sealed data to ipfs and get related cid
            char n_cid[CID_LENGTH];
            ocall_ipfs_add(&crust_status, p_sealed_data, sealed_data_size, n_cid, CID_LENGTH);
            free(p_sealed_data);
            if (CRUST_SUCCESS != crust_status)
            {
                break;
            }
            json::JSON sub_tree;
            sub_tree[MT_DATA_HASH] = hexstring_safe(reinterpret_cast<uint8_t *>(&sealed_hash), HASH_LENGTH);
            sub_tree[MT_CID] = std::string(n_cid, CID_LENGTH);
            tree[MT_LINKS].append(sub_tree);
            sealed_size += sealed_data_size;
            origin_size += *sealed_buffer_offset;
            block_num++;
        } while (0);

        // Compute tree root hash
        do
        {
            if (CRUST_SUCCESS != crust_status || tree[MT_LINKS].size() <= 0)
            {
                break;
            }
            size_t hash_buffer_size = tree[MT_LINKS].size() * HASH_LENGTH;
            uint8_t *sealed_hash_buffer = (uint8_t *)enc_malloc(hash_buffer_size);
            if (sealed_hash_buffer == NULL)
            {
                crust_status = CRUST_MALLOC_FAILED;
                break;
            }
            memset(sealed_hash_buffer, 0, hash_buffer_size);
            for (int i = 0; i < tree[MT_LINKS].size(); i++)
            {
                std::string tmp_hash = tree[MT_LINKS][i][MT_DATA_HASH].ToString();
                uint8_t *tmp_hash_u = hex_string_to_bytes(tmp_hash.c_str(), tmp_hash.size());
                if (tmp_hash_u == NULL)
                {
                    free(sealed_hash_buffer);
                    crust_status = CRUST_UNEXPECTED_ERROR;
                    break;
                }
                memcpy(sealed_hash_buffer + i * HASH_LENGTH, tmp_hash_u, HASH_LENGTH);
                free(tmp_hash_u);
            }
            if (CRUST_SUCCESS != crust_status)
            {
                break;
            }
            sgx_sha256_hash_t total_hash;
            sgx_sha256_msg(sealed_hash_buffer, hash_buffer_size, &total_hash);
            tree[MT_HASH] = hexstring_safe(reinterpret_cast<uint8_t *>(&total_hash), HASH_LENGTH);
            free(sealed_hash_buffer);
        } while (0);

        free(sealed_buffer);
        free(sealed_buffer_offset);
    }

    return crust_status;
}

/**
 * @description: Unseal file according to given path
 * @param data -> Pointer to sealed data
 * @param data_size -> To be sealed data size
 * @return: Unseal status
 */
crust_status_t storage_unseal_file(const char *data, size_t data_size)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    uint8_t *p_decrypted_data = NULL;
    uint32_t decrypted_data_len = 0;
    sgx_sha256_hash_t sealed_root;
    std::string sealed_root_str;

    // Allocate buffer for decrypted data
    sgx_sealed_data_t *p_sealed_data = (sgx_sealed_data_t *)enc_malloc(data_size);
    memset(p_sealed_data, 0, data_size);
    memcpy(p_sealed_data, data, data_size);
    decrypted_data_len = sgx_get_encrypt_txt_len(p_sealed_data);
    p_decrypted_data = (uint8_t *)enc_malloc(decrypted_data_len);
    if (p_decrypted_data == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(p_decrypted_data, 0, decrypted_data_len);

    // Do unseal
    sgx_status = sgx_unseal_data(p_sealed_data, NULL, NULL,
            p_decrypted_data, &decrypted_data_len);
    if (SGX_SUCCESS != sgx_status)
    {
        log_err("SGX unseal failed! Internal error:%lx\n", sgx_status);
        crust_status = CRUST_UNSEAL_DATA_FAILED;
        goto cleanup;
    }

    // Check if data is private data
    if (memcmp(p_decrypted_data, SWORKER_PRIVATE_TAG, strlen(SWORKER_PRIVATE_TAG)) == 0)
    {
        crust_status = CRUST_MALWARE_DATA_BLOCK;
        goto cleanup;
    }

    // Store unsealed data
    sgx_sha256_msg(reinterpret_cast<const uint8_t *>(data), data_size, &sealed_root);
    sealed_root_str = hexstring_safe(reinterpret_cast<const uint8_t *>(&sealed_root), HASH_LENGTH);
    ocall_store_unsealed_data(sealed_root_str.c_str(), p_decrypted_data, decrypted_data_len);


cleanup:
    if (p_decrypted_data != NULL)
        free(p_decrypted_data);

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
    SafeLock sf_lock(g_sealed_files_mutex);
    sf_lock.lock();
    Workload *wl = Workload::get_instance();
    bool is_deleted = false;
    for (auto it = wl->sealed_files.begin(); it != wl->sealed_files.end(); it++)
    {
        std::string cur_cid = (*it)[FILE_CID].ToString();
        if (cur_cid.compare(cid) == 0)
        {
            if ((*it)[FILE_STATUS].get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
            {
                log_info("file(%s) has been deleted!\n", cid);
                return CRUST_SUCCESS;
            }
            deleted_file = *it;
            is_deleted = true;
            if ((*it)[FILE_STATUS].get_char(ORIGIN_STATUS) == FILE_STATUS_UNVERIFIED)
            {
                wl->sealed_files.erase(it);
                break;
            }
            (*it)[FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
            break;
        }
    }
    sf_lock.unlock();
    // Print deleted info
    if (is_deleted)
    {
        log_info("Delete file:%s successfully!\n", cid);
    }
    else
    {
        log_warn("Delete file:%s failed(not found)!\n", cid);
    }

    // ----- Delete file related data ----- //
    if (is_deleted)
    {
        std::string del_cid = deleted_file[FILE_CID].ToString();
        // Delete real file
        ocall_ipfs_del(&crust_status, del_cid.c_str());
        // Delete file tree structure
        persist_del(del_cid);
        // Update workload spec info
        wl->set_wl_spec(deleted_file[FILE_STATUS].get_char(CURRENT_STATUS), -deleted_file[FILE_SIZE].ToInt());
    }

    return crust_status;
}

/**
 * @description: Check if to be sealed file is duplicated
 * @param cid -> IPFS content id
 * @return: 0 -> duplicated
 *          1 -> not duplicated
 *          2 -> Will be replaced by new file, but not report
 *          3 -> Will be replaced by new file, report again
 */
int check_file_dup(std::string cid)
{
    Workload *wl = Workload::get_instance();
    SafeLock cf_lock(g_sealed_files_mutex);
    cf_lock.lock();
    for (auto it = wl->sealed_files.begin(); it != wl->sealed_files.end(); it++)
    {
        if ((*it)[FILE_CID].ToString().compare(cid) == 0)
        {
            char cur_s = (*it)[FILE_STATUS].get_char(CURRENT_STATUS);
            char org_s = (*it)[FILE_STATUS].get_char(ORIGIN_STATUS);
            if (cur_s == FILE_STATUS_DELETED)
            {
                if (org_s == FILE_STATUS_VALID)
                {
                    wl->sealed_files.erase(it);
                    return 2;
                }
                if (org_s == FILE_STATUS_DELETED)
                {
                    wl->sealed_files.erase(it);
                    return 3;
                }
            }
            return 0;
        }
    }
    cf_lock.unlock();

    return 1;
}

/**
 * @description: Get the hashs of links from ipfs block
 * @param block_data -> ipfs block data
 * @param block_size -> ipfs block size
 * @param hashs -> Return hashs, which need to be released when used up
 * @return: Status
 */
crust_status_t get_hashs_from_block(uint8_t *block_data, size_t block_size, std::vector<uint8_t *> &hashs)
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
