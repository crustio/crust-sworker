#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "EJson.h"

using namespace std;

// Lock used to lock outside buffer
sgx_thread_mutex_t g_file_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

// Current node public and private key pair
extern sgx_thread_mutex_t g_new_files_mutex;
extern sgx_thread_mutex_t g_checked_files_mutex;

crust_status_t _storage_seal_file(json::JSON &tree_json, string path, string &tree, size_t &node_size, size_t &block_num);

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param p_tree -> Pointer to MerkleTree json structure buffer 
 * @param tree_len -> MerkleTree json structure buffer length
 * @param path -> Reference to file path
 * @param path_len -> Pointer to file path length
 * @param p_new_path -> Pointer to sealed data path
 * @return: Seal status
 */
crust_status_t storage_seal_file(const char *p_tree, size_t tree_len, const char *path, size_t path_len, char *p_new_path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Check if file number exceeds upper limit
    size_t file_num = 0;
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    file_num += wl->checked_files.size();
    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    sgx_thread_mutex_lock(&g_new_files_mutex);
    file_num += wl->new_files.size();
    sgx_thread_mutex_unlock(&g_new_files_mutex);

    if (file_num >= FILE_NUMBER_UPPER_LIMIT)
    {
        return CRUST_FILE_NUMBER_EXCEED;
    }

    // Validate MerkleTree
    json::JSON tree_json = json::JSON::Load(std::string(p_tree, tree_len));
    if (tree_json.size() == 0)
    {
        log_err("Storage: empty MerkleTree!");
        return CRUST_INVALID_MERKLETREE;
    }
    if (CRUST_SUCCESS != (crust_status = validate_merkletree_json(tree_json)))
    {
        return crust_status;
    }

    std::string org_root_hash_str = tree_json[MT_HASH].ToString();
    size_t org_node_size = tree_json[MT_SIZE].ToInt();
    std::string old_path(path, path_len);
    std::string new_tree;

    // ----- Physical operation ----- //
    // Do seal file
    size_t node_size = 0;
    size_t block_num = 0;
    crust_status = _storage_seal_file(tree_json, old_path, new_tree, node_size, block_num);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    std::string new_root_hash_str = tree_json[MT_HASH].ToString();

    // Rename old directory
    std::string new_path = old_path.substr(0, old_path.find(org_root_hash_str)) + new_root_hash_str;
    ocall_rename_dir(&crust_status, old_path.c_str(), new_path.c_str());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    memcpy(p_new_path, new_path.c_str(), new_path.size());

    // Pass new tree structure to APP
    ocall_store_sealed_merkletree(org_root_hash_str.c_str(), new_tree.c_str(), new_tree.size());

    // ----- Add corresponding metadata ----- //
    json::JSON file_entry_json;
    uint8_t *new_root_hash_u = hex_string_to_bytes(new_root_hash_str.c_str(), new_root_hash_str.size());
    if (new_root_hash_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    uint8_t *org_root_hash_u = hex_string_to_bytes(org_root_hash_str.c_str(), org_root_hash_str.size());
    if (org_root_hash_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    file_entry_json[FILE_HASH] = new_root_hash_u;
    file_entry_json[FILE_OLD_HASH] = org_root_hash_u;
    file_entry_json[FILE_SIZE] = node_size;
    file_entry_json[FILE_OLD_SIZE] = org_node_size;
    file_entry_json[FILE_BLOCK_NUM] = block_num;
    // Status indicates current new file's status, which must be one of valid, lost and unconfirmed
    file_entry_json[FILE_STATUS] = "000";
    free(new_root_hash_u);
    free(org_root_hash_u);

    // Store new tree structure
    crust_status = persist_set_unsafe(new_root_hash_str, (const uint8_t *)new_tree.c_str(), new_tree.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Store new tree meta data
    json::JSON tree_meta_json;
    tree_meta_json[FILE_OLD_HASH] = org_root_hash_str;
    tree_meta_json[FILE_OLD_SIZE] = org_node_size;
    std::string tree_meta_str = tree_meta_json.dump();
    crust_status = persist_set_unsafe((new_root_hash_str + "_meta"), (const uint8_t *)tree_meta_str.c_str(), tree_meta_str.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Print sealed file information
    log_info("Seal complete, file info; hash: %s -> size: %ld, status: unconfirmed\n",
            file_entry_json[FILE_HASH].ToString().c_str(),
            file_entry_json[FILE_SIZE].ToInt());

    // Add new file to buffer
    wl->add_new_file(file_entry_json);

    // Add info in workload spec
    wl->set_wl_spec(FILE_STATUS_UNCONFIRMED, file_entry_json[FILE_OLD_SIZE].ToInt());

    return crust_status;
}

/**
 * @description: Do seal file
 * @param tree_json -> Reference to current node json
 * @param path -> Origin data path
 * @param tree -> Sealed tree structure
 * @param node_size -> Current node data length
 * @param block_num -> Current block index
 * @return: Seal status
 */
crust_status_t _storage_seal_file(json::JSON &tree_json, string path, string &tree,
        size_t &node_size, size_t &block_num)
{
    if (tree_json.size() == 0)
        return CRUST_SUCCESS;

    crust_status_t crust_status = CRUST_SUCCESS;

    // ----- Deal with leaf node ----- //
    if (tree_json[MT_LINKS_NUM].ToInt() == 0)
    {
        std::string old_path;
        std::string old_hash_str = tree_json[MT_HASH].ToString();
        old_path.append(path).append("/").append(to_string(block_num)).append("_").append(old_hash_str);

        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_size = 0;
        uint8_t *file_data_r = NULL;
        sgx_sha256_hash_t new_hash;
        uint8_t *file_data = NULL;
        size_t file_data_len = 0;
        std::string hex_new_hash_str;
        string new_path;
        sgx_sha256_hash_t got_org_hash;
        uint8_t *p_org_hash = NULL;

        // Get file data
        sgx_thread_mutex_lock(&g_file_buffer_mutex);
        ocall_get_storage_file(&crust_status, old_path.c_str(), &file_data, &file_data_len);
        if (CRUST_SUCCESS != crust_status || file_data == NULL)
        {
            log_err("Get file:%s data failed!\n", old_path.c_str());
            goto sealend;
        }

        // --- Seal file data --- //
        // Check file size
        if (tree_json[MT_SIZE].ToInt() != (long long)file_data_len)
        {
            crust_status = CRUST_STORAGE_NEW_FILE_SIZE_ERROR;
            goto sealend;
        }
        // Check file hash
        file_data_r = (uint8_t *)enc_malloc(file_data_len);
        if (file_data_r == NULL)
        {
            log_err("Malloc memory failed!\n");
            goto sealend;
        }
        memset(file_data_r, 0, file_data_len);
        memcpy(file_data_r, file_data, file_data_len);
        sgx_sha256_msg(file_data_r, file_data_len, &got_org_hash);
        p_org_hash = hex_string_to_bytes(old_hash_str.c_str(), old_hash_str.size());
        if (p_org_hash == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            goto sealend;
        }
        if (memcmp(p_org_hash, &got_org_hash, HASH_LENGTH) != 0)
        {
            crust_status = CRUST_STORAGE_UNEXPECTED_FILE_BLOCK;
            goto sealend;
        }
        // Do seal
        crust_status = seal_data_mrsigner(file_data_r, file_data_len,
                (sgx_sealed_data_t **)&p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }

        // Get new hash
        sgx_sha256_msg(p_sealed_data, sealed_data_size, &new_hash);
        hex_new_hash_str = hexstring_safe(new_hash, HASH_LENGTH);
        new_path.append(path)
            .append("/")
            .append(to_string(block_num))
            .append("_")
            .append(hex_new_hash_str);
        // Replace old file with new file
        ocall_replace_file(&crust_status, old_path.c_str(), new_path.c_str(), p_sealed_data, sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }
        tree_json[MT_HASH] = hex_new_hash_str;
        node_size += sealed_data_size;
        block_num++;

        // Construct tree string
        // Note: Cannot change append sequence!
        tree.append("{\"" MT_LINKS_NUM "\":").append(to_string(tree_json[MT_LINKS_NUM].ToInt())).append(",");
        tree.append("\"" MT_HASH "\":\"").append(tree_json[MT_HASH].ToString()).append("\",");
        tree.append("\"" MT_SIZE "\":").append(to_string(sealed_data_size)).append("}");

    sealend:

        sgx_thread_mutex_unlock(&g_file_buffer_mutex);

        if (file_data_r != NULL)
            free(file_data_r);

        if (p_sealed_data != NULL)
            free(p_sealed_data);

        if (p_org_hash != NULL)
            free(p_org_hash);

        return crust_status;
    }

    // ----- Deal with non-leaf node ----- //
    // Construct tree string
    tree.append("{\"" MT_LINKS "\": [");

    size_t sub_hashs_len = tree_json[MT_LINKS_NUM].ToInt() * HASH_LENGTH;
    uint8_t *sub_hashs = (uint8_t *)enc_malloc(sub_hashs_len);
    if (sub_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(sub_hashs, 0, sub_hashs_len);
    size_t cur_size = 0;
    for (int i = 0; i < tree_json[MT_LINKS_NUM].ToInt(); i++)
    {
        crust_status = _storage_seal_file(tree_json[MT_LINKS][i], path, tree, cur_size, block_num);
        if (CRUST_SUCCESS != crust_status)
        {
            goto cleanup;
        }
        uint8_t *p_new_hash = hex_string_to_bytes(tree_json[MT_LINKS][i][MT_HASH].ToString().c_str(), HASH_LENGTH * 2);
        if (p_new_hash == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            goto cleanup;
        }
        memcpy(sub_hashs + i * HASH_LENGTH, p_new_hash, HASH_LENGTH);
        free(p_new_hash);
        if (i != tree_json[MT_LINKS_NUM].ToInt() - 1)
        {
            tree.append(",");
        }
    }
    // Get new hash
    sgx_sha256_hash_t new_hash;
    sgx_sha256_msg(sub_hashs, sub_hashs_len, &new_hash);
    tree_json[MT_HASH] = hexstring_safe(new_hash, HASH_LENGTH);

    // Construct tree string
    tree.append("],\"" MT_LINKS_NUM "\":").append(to_string(tree_json[MT_LINKS_NUM].ToInt())).append(",");
    tree.append("\"" MT_HASH "\":\"").append(tree_json[MT_HASH].ToString()).append("\",");
    tree.append("\"" MT_SIZE "\":").append(to_string(cur_size)).append("}");

    node_size += cur_size;

cleanup:

    if (sub_hashs != NULL)
        free(sub_hashs);

    return crust_status;
}

/**
 * @description: Unseal file according to given path
 * @param files -> Files in root directory
 * @param files_num -> Files number in root directory
 * @param p_dir -> Root directory path
 * @param p_new_path -> Pointer to unsealed data path
 * @return: Unseal status
 */
crust_status_t storage_unseal_file(char **files, size_t files_num, const char *p_dir, char *p_new_path)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    vector<string> files_v(files, files + files_num);          // Get all data file path
    uint8_t *p_sealed_data = NULL;                             // Get from outside file
    size_t sealed_data_size_r = 0;                             // Data size got from outside file
    sgx_sealed_data_t *p_sealed_data_r = NULL;                 // Malloc in enclave for unseal
    uint8_t *p_decrypted_data = NULL;                          // Buffer malloced for unseal
    uint32_t decrypted_data_len = 0;                           // Malloced buffer size
    uint32_t decrypted_data_len_r = 0;                         // Unsealed buffer size
    std::string dir(p_dir);                                    // Parent directory path
    std::string up_dir = dir.substr(0, dir.find_last_of("/")); // Directory contains parent dir

    // Judge if new tree hash exists in DB
    std::string new_root_hash_str = dir.substr(dir.find_last_of("/") + 1, dir.size());
    uint8_t *p_meta = NULL;
    size_t meta_len;
    crust_status = persist_get_unsafe((new_root_hash_str + "_meta"), &p_meta, &meta_len);
    if (CRUST_SUCCESS != crust_status || p_meta == NULL)
    {
        return CRUST_STORAGE_UNSEAL_FILE_FAILED;
    }
    std::string tree_meta(reinterpret_cast<char *>(p_meta), meta_len);
    json::JSON meta_json = json::JSON::Load(tree_meta);
    std::string new_dir(up_dir);
    new_dir.append("/").append(meta_json[FILE_OLD_HASH].ToString());
    free(p_meta);

    // Do unseal file
    sgx_thread_mutex_lock(&g_file_buffer_mutex);
    for (auto path : files_v)
    {
        std::string tag = path.substr(0, path.find("_"));
        path = dir + "/" + path;

        // ----- Unseal file data ----- //
        // Get file data
        ocall_get_storage_file(&crust_status, path.c_str(), &p_sealed_data, &sealed_data_size_r);
        if (CRUST_SUCCESS != crust_status || p_sealed_data == NULL)
        {
            goto cleanup;
        }
        // Allocate buffer for sealed data
        p_sealed_data_r = (sgx_sealed_data_t *)enc_malloc(sealed_data_size_r);
        if (p_sealed_data_r == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            goto cleanup;
        }
        memset(p_sealed_data_r, 0, sealed_data_size_r);
        memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size_r);
        // Allocate buffer for decrypted data
        decrypted_data_len_r = sgx_get_encrypt_txt_len(p_sealed_data_r);
        if (decrypted_data_len_r > decrypted_data_len)
        {
            decrypted_data_len = decrypted_data_len_r;
            p_decrypted_data = (uint8_t *)enc_realloc(p_decrypted_data, decrypted_data_len);
            if (p_decrypted_data == NULL)
            {
                crust_status = CRUST_MALLOC_FAILED;
                goto cleanup;
            }
        }
        memset(p_decrypted_data, 0, decrypted_data_len);

        // Do unseal
        sgx_status = sgx_unseal_data(p_sealed_data_r, NULL, NULL,
                p_decrypted_data, &decrypted_data_len_r);
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

        // Replace data file
        sgx_sha256_hash_t new_hash;
        sgx_sha256_msg(p_decrypted_data, decrypted_data_len_r, &new_hash);
        std::string new_path;
        std::string hex_new_hash_str = hexstring_safe(new_hash, HASH_LENGTH);
        new_path.append(dir).append("/").append(tag).append("_").append(hex_new_hash_str);
        ocall_replace_file(&crust_status, path.c_str(), new_path.c_str(), p_decrypted_data, decrypted_data_len_r);
        if (CRUST_SUCCESS != crust_status)
        {
            crust_status = CRUST_STORAGE_UPDATE_FILE_FAILED;
            goto cleanup;
        }

        // Free buffer
        free(p_sealed_data_r);
        p_sealed_data_r = NULL;
    }

    // Rename directory
    ocall_rename_dir(&crust_status, dir.c_str(), new_dir.c_str());
    memcpy(p_new_path, new_dir.c_str(), new_dir.size());

cleanup:

    sgx_thread_mutex_unlock(&g_file_buffer_mutex);

    if (p_sealed_data_r != NULL)
        free(p_sealed_data_r);

    if (p_decrypted_data != NULL)
        free(p_decrypted_data);

    return crust_status;
}

/**
 * @description: Confirm new file
 * @param hash -> Pointer to new file hash
 * @return: Confirm status
 */
crust_status_t storage_confirm_file(const char *hash)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    json::JSON confirmed_file;
    Workload *wl = Workload::get_instance();

    // ----- Confirm file items in checked_files ----- //
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    bool is_confirmed = false;
    for (auto it = wl->checked_files.rbegin(); it != wl->checked_files.rend(); it++)
    {
        if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
        {
            auto status = &(*it)[FILE_STATUS];
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_UNCONFIRMED)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_VALID);
            }
            is_confirmed = true;
            confirmed_file = *it;
            break;
        }
    }
    // Confirm file items in new_files
    if (!is_confirmed)
    {
        sgx_thread_mutex_lock(&g_new_files_mutex);
        for (auto it = wl->new_files.rbegin(); it != wl->new_files.rend(); it++)
        {
            if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
            {
                auto status = &(*it)[FILE_STATUS];
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_UNCONFIRMED)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_VALID);
                    is_confirmed = true;
                    confirmed_file = *it;
                    break;
                }
            }
        }
        sgx_thread_mutex_unlock(&g_new_files_mutex);
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
    // Print confirmed info
    if (is_confirmed)
    {
        log_info("Confirm file:%s successfully! Will be validated.\n", confirmed_file[FILE_HASH].ToString().c_str());
    }
    else
    {
        log_warn("Confirm file:%s failed(not found)!\n", confirmed_file[FILE_HASH].ToString().c_str());
    }

    // Set workload spec information
    if (is_confirmed)
    {
        wl->set_wl_spec(FILE_STATUS_VALID, FILE_STATUS_UNCONFIRMED, confirmed_file[FILE_OLD_SIZE].ToInt());
    }

    return crust_status;
}

/**
 * @description: Delete meaningful file
 * @param hash -> File root hash
 * @return: Delete status
 */
crust_status_t storage_delete_file(const char *hash)
{
    // ----- Delete file items in metadata ----- //
    json::JSON deleted_file;
    crust_status_t crust_status = CRUST_SUCCESS;

    // ----- Delete file items in checked_files ----- //
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    Workload *wl = Workload::get_instance();
    bool is_deleted = false;
    for (size_t i = 0; i < wl->checked_files.size(); i++)
    {
        std::string hash_str = wl->checked_files[i][FILE_HASH].ToString();
        if (hash_str.compare(hash) == 0)
        {
            deleted_file = wl->checked_files[i];
            wl->checked_files[i][FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
            is_deleted = true;
            break;
        }
    }
    // Delete file items in new_files
    if (!is_deleted)
    {
        sgx_thread_mutex_lock(&g_new_files_mutex);
        for (auto it = wl->new_files.rbegin(); it != wl->new_files.rend(); it++)
        {
            std::string hash_str = (*it)[FILE_HASH].ToString();
            if (hash_str.compare(hash) == 0)
            {
                deleted_file = *it;
                wl->new_files.erase((++it).base());
                is_deleted = true;
                break;
            }
        }
        sgx_thread_mutex_unlock(&g_new_files_mutex);
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
    // Print deleted info
    if (is_deleted)
    {
        log_info("Delete file:%s successfully!\n", deleted_file[FILE_HASH].ToString().c_str());
    }
    else
    {
        log_warn("Delete file:%s failed(not found)!\n", deleted_file[FILE_HASH].ToString().c_str());
    }

    // ----- Delete file related data ----- //
    if (is_deleted)
    {
        // Delete file tree structure
        persist_del(deleted_file[FILE_HASH].ToString());
        // Delete file metadata
        persist_del(deleted_file[FILE_HASH].ToString() + "_meta");
        // Update workload spec info
        wl->set_wl_spec(deleted_file[FILE_STATUS].get_char(CURRENT_STATUS), -deleted_file[FILE_OLD_SIZE].ToInt());
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
        
        uint8_t* hash = (uint8_t *)enc_malloc(32);
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
