#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "EJson.h"

using namespace std;

// Lock used to lock outside buffer
sgx_thread_mutex_t g_file_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

// Current node public and private key pair
extern ecc_key_pair id_key_pair;
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
 * */
crust_status_t storage_seal_file(const char *p_tree, size_t tree_len, const char *path, size_t path_len, char *p_new_path)
{
    crust_status_t crust_status = CRUST_SUCCESS;

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

    std::string org_root_hash_str = tree_json[FILE_HASH].ToString();
    size_t org_node_size = tree_json[FILE_SIZE].ToInt();
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
    new_tree.erase(new_tree.size() - 1, 1);
    std::string new_root_hash_str = tree_json[FILE_HASH].ToString();

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
    // Store Meaningful file entry to enclave metadata
    json::JSON file_entry_json;
    file_entry_json[FILE_HASH] = new_root_hash_str;
    file_entry_json[FILE_SIZE] = node_size;
    // Status indicates current new file's status, which must be one of valid, lost and unconfirmed
    file_entry_json[FILE_STATUS] = FILE_STATUS_UNCONFIRMED;
    crust_status = id_metadata_set_or_append(ID_FILE, file_entry_json, ID_APPEND);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Store new tree structure
    crust_status = persist_set(new_root_hash_str, (const uint8_t*)new_tree.c_str(), new_tree.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Store new tree meta data
    json::JSON tree_meta_json;
    tree_meta_json[FILE_OLD_HASH] = org_root_hash_str;
    tree_meta_json[FILE_OLD_SIZE] = org_node_size;
    tree_meta_json[FILE_BLOCK_NUM] = block_num;
    std::string tree_meta_str = tree_meta_json.dump();
    crust_status = persist_set((new_root_hash_str+"_meta"), (const uint8_t*)tree_meta_str.c_str(), tree_meta_str.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Print sealed file information
    log_info("Seal complete, file info; hash: %s -> size: %d, status: %s\n",
            file_entry_json["hash"].ToString().c_str(), 
            file_entry_json["size"].ToInt(), 
            file_entry_json["status"].ToString().c_str());

    // Add new file to buffer
    Workload::get_instance()->add_new_file(file_entry_json);

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
 * */
crust_status_t _storage_seal_file(json::JSON &tree_json, string path, string &tree,
        size_t &node_size, size_t &block_num)
{
    if (tree_json.size() == 0)
        return CRUST_SUCCESS;

    crust_status_t crust_status = CRUST_SUCCESS;

    // ----- Deal with leaf node ----- //
    if (tree_json["links_num"].ToInt() == 0)
    {
        std::string old_path;
        std::string old_hash_str = tree_json[FILE_HASH].ToString();
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
            sgx_thread_mutex_unlock(&g_file_buffer_mutex);
            goto sealend;
        }

        // --- Seal file data --- //
        // Check file size
        if (tree_json[FILE_SIZE].ToInt() != (long long)file_data_len)
        {
            crust_status = CRUST_STORAGE_NEW_FILE_SIZE_ERROR;
            goto sealend;
        }
        // Check file hash
        file_data_r = (uint8_t*)enc_malloc(file_data_len);
        memset(file_data_r, 0, file_data_len);
        memcpy(file_data_r, file_data, file_data_len);
        sgx_sha256_msg(file_data_r, file_data_len, &got_org_hash);
        p_org_hash = hex_string_to_bytes(old_hash_str.c_str(), old_hash_str.size());
        if (memcmp(p_org_hash, &got_org_hash, HASH_LENGTH) != 0)
        {
            crust_status = CRUST_STORAGE_UNEXPECTED_FILE_BLOCK;
            goto sealend;
        }
        // Do seal
        sgx_thread_mutex_unlock(&g_file_buffer_mutex);
        crust_status = seal_data_mrenclave(file_data_r, file_data_len, 
                (sgx_sealed_data_t**)&p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }

        // Get new hash
        sgx_sha256_msg(p_sealed_data, sealed_data_size, &new_hash);
        hex_new_hash_str = hexstring_safe(new_hash, HASH_LENGTH);
        new_path.append(path)
            .append("/").append(to_string(block_num))
            .append("_").append(hex_new_hash_str);
        // Replace old file with new file
        ocall_replace_file(&crust_status, old_path.c_str(), new_path.c_str(), p_sealed_data, sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }
        tree_json[FILE_HASH] = hex_new_hash_str;
        node_size += sealed_data_size;
        block_num++;

        // Construct tree string
        // Note: Cannot change append sequence!
        tree.append("{\"links_num\":").append(to_string(tree_json["links_num"].ToInt())).append(",");
        tree.append("\"hash\":\"").append(tree_json[FILE_HASH].ToString()).append("\",");
        tree.append("\"size\":").append(to_string(sealed_data_size)).append("},");

    sealend:

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
    tree.append("{\"links\": [");

    size_t sub_hashs_len = tree_json["links_num"].ToInt() * HASH_LENGTH;
    uint8_t *sub_hashs = (uint8_t*)enc_malloc(sub_hashs_len);
    memset(sub_hashs, 0, sub_hashs_len);
    size_t cur_size = 0;
    for (int i = 0; i < tree_json["links_num"].ToInt(); i++)
    {
        crust_status = _storage_seal_file(tree_json["links"][i], path, tree, cur_size, block_num);
        if (CRUST_SUCCESS != crust_status)
        {
            goto cleanup;
        }
        uint8_t *p_new_hash = hex_string_to_bytes(tree_json["links"][i][FILE_HASH].ToString().c_str(), HASH_LENGTH * 2);
        if (p_new_hash == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            goto cleanup;
        }
        memcpy(sub_hashs + i * HASH_LENGTH, p_new_hash, HASH_LENGTH);
        free(p_new_hash);
    }
    // Get new hash
    sgx_sha256_hash_t new_hash;
    sgx_sha256_msg(sub_hashs, sub_hashs_len, &new_hash);
    tree_json[FILE_HASH] = hexstring_safe(new_hash, HASH_LENGTH);

    // Construct tree string
    tree.erase(tree.size() - 1, 1);
    tree.append("],\"links_num\":").append(to_string(tree_json["links_num"].ToInt())).append(",");
    tree.append("\"hash\":\"").append(tree_json[FILE_HASH].ToString()).append("\",");
    tree.append("\"size\":").append(to_string(cur_size)).append("},");

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
 * */
crust_status_t storage_unseal_file(char **files, size_t files_num, const char *p_dir, char *p_new_path)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    vector<string> files_v(files, files + files_num);   // Get all data file path
    uint8_t *p_sealed_data = NULL;  // Get from outside file
    size_t sealed_data_size_r = 0;  // Data size got from outside file
    sgx_sealed_data_t *p_sealed_data_r = NULL;  // Malloc in enclave for unseal
    uint8_t *p_decrypted_data = NULL;   // Buffer malloced for unseal
    uint32_t decrypted_data_len = 0;    // Malloced buffer size
    uint32_t decrypted_data_len_r = 0;  // Unsealed buffer size
    std::string dir(p_dir); // Parent directory path
    std::string up_dir = dir.substr(0, dir.find_last_of("/")); // Directory contains parent dir

    // Judge if new tree hash exists in DB
    std::string new_root_hash_str = dir.substr(dir.find_last_of("/") + 1, dir.size());
    uint8_t *p_meta = NULL;
    size_t meta_len;
    crust_status = persist_get((new_root_hash_str+"_meta"), &p_meta, &meta_len);
    if (CRUST_SUCCESS != crust_status || p_meta == NULL)
    {
        return CRUST_STORAGE_UNSEAL_FILE_FAILED;
    }
    std::string tree_meta(reinterpret_cast<char*>(p_meta), meta_len);
    json::JSON meta_json = json::JSON::Load(tree_meta);
    std::string new_dir(up_dir);
    new_dir.append("/").append(meta_json[FILE_OLD_HASH].ToString());
    free(p_meta);
    
    // Do unseal file
    for (auto path : files_v)
    {
        std::string tag = path.substr(0, path.find("_"));
        path = dir + "/" + path;

        // ----- Unseal file data ----- //
        // Get file data
        sgx_thread_mutex_lock(&g_file_buffer_mutex);
        ocall_get_storage_file(&crust_status, path.c_str(), &p_sealed_data, &sealed_data_size_r);
        if (CRUST_SUCCESS != crust_status || p_sealed_data == NULL)
        {
            sgx_thread_mutex_unlock(&g_file_buffer_mutex);
            goto cleanup;
        }
        // Allocate buffer for sealed data
        p_sealed_data_r = (sgx_sealed_data_t*)enc_malloc(sealed_data_size_r);
        if (p_sealed_data_r == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            sgx_thread_mutex_unlock(&g_file_buffer_mutex);
            goto cleanup;
        }
        memset(p_sealed_data_r, 0, sealed_data_size_r);
        memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size_r);
        sgx_thread_mutex_unlock(&g_file_buffer_mutex);
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
        if (memcmp(p_decrypted_data, TEE_PRIVATE_TAG, strlen(TEE_PRIVATE_TAG)) == 0)
        {
            crust_status = CRUST_MALWARE_DATA_BLOCK;
            goto cleanup;
        }

        // Replace data file
        sgx_sha256_hash_t new_hash;
        sgx_sha256_msg(p_decrypted_data, decrypted_data_len_r, &new_hash);
        std::string new_path;
        std::string hex_new_hash_str = hexstring_safe(new_hash, HASH_LENGTH);
        new_path.append(dir).append("/").append(tag).append("_")
            .append(hex_new_hash_str);
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
 * */
crust_status_t storage_confirm_file(const char *hash)
{
    sgx_thread_mutex_lock(&g_metadata_mutex);

    crust_status_t crust_status = CRUST_SUCCESS;
    json::JSON confirmed_file;
    Workload *wl = Workload::get_instance();

    // ----- Find file entry by hash ----- //
    // Get metadata
    json::JSON meta_json_org;
    id_get_metadata(meta_json_org, false);
    if (!meta_json_org.hasKey(ID_FILE))
    {
        sgx_thread_mutex_unlock(&g_metadata_mutex);
        return CRUST_STORAGE_NEW_FILE_NOTFOUND;
    }
    for (auto it = meta_json_org[ID_FILE].ArrayRange().object->rbegin(); 
            it != meta_json_org[ID_FILE].ArrayRange().object->rend(); it++)
    {
        if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
        {
            if ((*it)[FILE_STATUS].ToString().compare(FILE_STATUS_UNCONFIRMED) == 0)
            {
                (*it)[FILE_STATUS] = FILE_STATUS_VALID;
                confirmed_file = *it;
            }
            break;
        }
    }
    // Update metadata
    if (CRUST_SUCCESS != (crust_status = id_metadata_set_or_append(ID_FILE, 
                    meta_json_org[ID_FILE], ID_UPDATE, false)))
    {
        log_err("Conirm file failed!Update metadata failed!Error code:%lx\n", crust_status);
        sgx_thread_mutex_unlock(&g_metadata_mutex);
        return crust_status;
    }
    sgx_thread_mutex_unlock(&g_metadata_mutex);
    // Print confirmed info
    if (confirmed_file.hasKey(FILE_HASH))
    {
        log_info("Confirm file:%s successfully! Will be validated.\n", confirmed_file[FILE_HASH].ToString().c_str());
    }
    else
    {
        log_warn("Confirm file:%s failed(not found)!\n", confirmed_file[FILE_HASH].ToString().c_str());
    }

    // ----- Confirm file items in checked_files ----- //
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    bool is_confirmed = false;
    for (auto it = wl->checked_files.rbegin(); it != wl->checked_files.rend(); it++)
    {
        if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
        {
            if ((*it)[FILE_STATUS].ToString().compare(FILE_STATUS_UNCONFIRMED) == 0)
            {
                (*it)[FILE_STATUS] = FILE_STATUS_VALID;
            }
            is_confirmed = true;
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
                if ((*it)[FILE_STATUS].ToString().compare(FILE_STATUS_UNCONFIRMED) == 0)
                {
                    (*it)[FILE_STATUS] = FILE_STATUS_VALID;
                }
            }
        }
        sgx_thread_mutex_unlock(&g_new_files_mutex);
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    // Report real-time order file
    if (confirmed_file.hasKey(FILE_HASH))
    {
        wl->add_order_file(make_pair(confirmed_file[FILE_HASH].ToString(), confirmed_file[FILE_SIZE].ToInt()));
    }

    return crust_status;
}

/**
 * @description: Delete meaningful file
 * @param hash -> File root hash
 * @return: Delete status
 * */
crust_status_t storage_delete_file(const char *hash)
{
    // ----- Delete file items in metadata ----- //
    sgx_thread_mutex_lock(&g_metadata_mutex);
    std::string deleted_file;
    // Get meaningful file
    json::JSON meta_json_org;
    id_get_metadata(meta_json_org, false);
    if (!meta_json_org.hasKey(ID_FILE))
    {
        sgx_thread_mutex_unlock(&g_metadata_mutex);
        return CRUST_STORAGE_FILE_NOTFOUND;
    }
    // Do delete
    auto p_arry = meta_json_org[ID_FILE].ArrayRange();
    for (auto it = p_arry.object->rbegin(); it != p_arry.object->rend(); it++)
    {
        if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
        {
            deleted_file = (*it)[FILE_HASH].ToString();
            p_arry.object->erase((++it).base());
            break;
        }
    }
    // Update metadata
    crust_status_t crust_status = CRUST_SUCCESS;
    if (CRUST_SUCCESS != (crust_status = id_metadata_set_or_append(ID_FILE, 
                    meta_json_org[ID_FILE], ID_UPDATE, false)))
    {
        log_err("Delete file failed!Update metadata failed!Error code:%lx\n", crust_status);
        sgx_thread_mutex_unlock(&g_metadata_mutex);
        return crust_status;
    }
    sgx_thread_mutex_unlock(&g_metadata_mutex);
    // Print deleted info
    if (deleted_file.size() > 0)
    {
        log_info("Delete file:%s successfully!\n", deleted_file.c_str());
    }
    else
    {
        log_warn("Delete file:%s failed(not found)!\n", deleted_file.c_str());
    }

    // ----- Delete file items in checked_files ----- //
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    Workload *wl = Workload::get_instance();
    bool is_deleted = false;
    for (auto it = wl->checked_files.rbegin(); it != wl->checked_files.rend(); it++)
    {
        if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
        {
            wl->checked_files.erase((++it).base());
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
            if ((*it)[FILE_HASH].ToString().compare(hash) == 0)
            {
                wl->new_files.erase((++it).base());
                break;
            }
        }
        sgx_thread_mutex_unlock(&g_new_files_mutex);
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    // ----- Delete file related data ----- //
    if (deleted_file.size() > 0)
    {
        // Delete file tree structure
        persist_del(deleted_file);
        // Delete file metadata
        persist_del(deleted_file+"_meta");
    }

    return crust_status;
}
