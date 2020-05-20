#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "EJson.h"

using namespace std;

// Old tree root hash to pair which consists of serialized old tree and leaf position and total size
map<vector<uint8_t>, tuple<string,size_t,size_t>> tree_meta_map;
// Map used to store sealed tree root to sealed tree root node
map<vector<uint8_t>, MerkleTree *> new_tree_map;
// Lock used to lock outside buffer
sgx_thread_mutex_t g_file_buffer_mutex;

// Current node public and private key pair
extern ecc_key_pair id_key_pair;

crust_status_t _storage_seal_file(MerkleTree *root, string path, string &tree, size_t &node_size, size_t &block_num);

/**
 * @description: Validate merkle tree and storage tree related meta data
 * @param root_hash -> Merkle tree root hash
 * @param hash_len -> Merkle tree root hash length
 * @return: Validate status
 * */
crust_status_t storage_validate_merkle_tree_old(MerkleTree *root, size_t *snapshot_pos)
{
    // Check duplicated
    vector<uint8_t> root_hash_v(root->hash, root->hash + HASH_LENGTH);
    if (tree_meta_map.find(root_hash_v) != tree_meta_map.end())
    {
        // Get current block position
        auto entry = tree_meta_map[root_hash_v];
        string ser_tree = std::get<0>(entry);
        size_t epos = std::get<1>(entry);
        size_t spos = 0;
        size_t acc = 0;
        if (epos != std::string::npos)
        {
            while (spos < epos)
            {
                spos = ser_tree.find(LEAF_SEPARATOR, spos) + strlen(LEAF_SEPARATOR);
                acc++;
            }
            *snapshot_pos = acc;
        }
        return CRUST_MERKLETREE_DUPLICATED;
    }

    // Do validation
    if (CRUST_SUCCESS != validate_merkle_tree_c(root))
    {
        return CRUST_INVALID_MERKLETREE;
    }

    // Serialize Merkle tree
    string ser_tree = serialize_merkletree_to_json_string(root);
    log_info("size:%d, serialized tree:%s\n", ser_tree.size(), ser_tree.c_str());

    // Record position of first leaf node
    size_t spos = ser_tree.find(LEAF_SEPARATOR);

    // Get vector of root hash
    vector<uint8_t> hash_v(root->hash, root->hash + HASH_LENGTH);

    // Record merkle tree metadata
    tree_meta_map[hash_v] = make_tuple(ser_tree, spos, 0);

    return CRUST_SUCCESS;
}

/**
 * @description: Validate merkle tree and storage tree related meta data
 * @param root_hash -> Merkle tree root hash
 * @param hash_len -> Merkle tree root hash length
 * @return: Validate status
 * */
crust_status_t storage_validate_merkle_tree(MerkleTree *root)
{
    return validate_merkle_tree_c(root);
}

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param root -> MerkleTree root node
 * @param path -> Reference to file path
 * @param tree -> New MerkleTree
 * @return: Seal status
 * */
crust_status_t storage_seal_file(MerkleTree *root, const char *path, size_t path_len, char *p_new_path)
{
    std::string org_root_hash_str(root->hash, HASH_LENGTH * 2);
    std::string old_path(path, path_len);
    std::string new_tree;

    // Do seal file
    size_t node_size = 0;
    size_t block_num = 0;
    crust_status_t crust_status = _storage_seal_file(root, old_path, new_tree, node_size, block_num);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    new_tree.erase(new_tree.size() - 1, 1);
    std::string new_root_hash_str(root->hash, HASH_LENGTH * 2);

    // Store Meaningful file entry to enclave metadata
    json::JSON file_entry_json;
    file_entry_json["hash"] = new_root_hash_str;
    file_entry_json["size"] = node_size;
    crust_status = id_metadata_set_or_append(MEANINGFUL_FILE_DB_TAG, file_entry_json, ID_APPEND);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    Workload::get_instance()->files_json.append(file_entry_json);

    // Store new tree structure
    std::string new_tree_meta_data;
    new_tree_meta_data.append(new_tree);
    crust_status = persist_set(new_root_hash_str.c_str(), (const uint8_t*)new_tree_meta_data.c_str(), new_tree_meta_data.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Store new tree meta data
    json::JSON tree_meta_json;
    tree_meta_json["old_hash"] = org_root_hash_str;
    tree_meta_json["size"] = node_size;
    std::string tree_meta_str = tree_meta_json.dump();
    crust_status = persist_set((new_root_hash_str+"_meta").c_str(), (const uint8_t*)tree_meta_str.c_str(), tree_meta_str.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Pass new tree structure to APP
    ocall_store_sealed_merkletree(org_root_hash_str.c_str(), new_tree.c_str(), new_tree.size());

    // Rename old directory
    std::string new_path = old_path.substr(0, old_path.find(org_root_hash_str)) + new_root_hash_str;
    ocall_rename_dir(&crust_status, old_path.c_str(), new_path.c_str());
    memcpy(p_new_path, new_path.c_str(), new_path.size());

    json::JSON cur_data;
    id_get_metadata(cur_data);

    return crust_status;
}

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param root -> MerkleTree root node
 * @param path -> Reference to file path
 * @param tree -> New MerkleTree
 * @return: Seal status
 * */
crust_status_t _storage_seal_file(MerkleTree *root, string path, string &tree, size_t &node_size, size_t &block_num)
{
    if (root == NULL)
        return CRUST_SUCCESS;

    crust_status_t crust_status = CRUST_SUCCESS;

    // ----- Deal with leaf node ----- //
    if (root->links_num == 0)
    {
        std::string old_path;
        std::string old_hash_str = std::string(root->hash);
        old_path.append(path).append("/").append(to_string(block_num)).append("_").append(old_hash_str);

        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_size = 0;
        uint8_t *file_data_r = NULL;
        sgx_sha256_hash_t new_hash;
        uint8_t *file_data = NULL;
        size_t file_data_len = 0;
        char *hex_new_hash;
        string new_path;

        // Get file data
        sgx_thread_mutex_lock(&g_file_buffer_mutex);
        ocall_get_storage_file(&crust_status, old_path.c_str(), &file_data, &file_data_len);
        if (CRUST_SUCCESS != crust_status || file_data == NULL)
        {
            log_err("Get file:%s data failed!\n", old_path.c_str());
            sgx_thread_mutex_unlock(&g_file_buffer_mutex);
            goto sealend;
        }

        // Seal file data
        file_data_r = (uint8_t*)malloc(file_data_len);
        memset(file_data_r, 0, file_data_len);
        memcpy(file_data_r, file_data, file_data_len);
        sgx_thread_mutex_unlock(&g_file_buffer_mutex);
        crust_status = seal_data_mrenclave(file_data_r, file_data_len, 
                (sgx_sealed_data_t**)&p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }

        // Get new hash
        sgx_sha256_msg(p_sealed_data, sealed_data_size, &new_hash);
        hex_new_hash = hexstring(new_hash, HASH_LENGTH);
        new_path.append(path).append("/").append(to_string(block_num)).append("_").append(hex_new_hash);
        // Replace old file with new file
        ocall_replace_file(&crust_status, old_path.c_str(), new_path.c_str(), p_sealed_data, sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }
        root->hash = hex_new_hash;
        node_size += sealed_data_size;
        block_num++;

        // Construct tree string
        // note: Cannot change append sequence!
        tree.append("{\"links_num\":").append(to_string(root->links_num)).append(",");
        tree.append("\"hash\":\"").append(root->hash, HASH_LENGTH * 2).append("\",");
        tree.append("\"size\":").append(to_string(sealed_data_size)).append("},");

    sealend:

        if (file_data_r != NULL)
            free(file_data_r);

        if (p_sealed_data != NULL)
            free(p_sealed_data);

        return crust_status;
    }

    // ----- Deal with non-leaf node ----- //
    // Construct tree string
    tree.append("{\"links\": [");

    size_t sub_hashs_len = root->links_num * HASH_LENGTH;
    uint8_t *sub_hashs = (uint8_t*)malloc(sub_hashs_len);
    memset(sub_hashs, 0, sub_hashs_len);
    char *hex_new_hash = NULL;
    size_t cur_size = 0;
    for (size_t i = 0; i < root->links_num; i++)
    {
        crust_status = _storage_seal_file(root->links[i], path, tree, cur_size, block_num);
        if (CRUST_SUCCESS != crust_status)
        {
            goto cleanup;
        }
        uint8_t *p_new_hash = hex_string_to_bytes(root->links[i]->hash, HASH_LENGTH * 2);
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
    hex_new_hash = hexstring(new_hash, HASH_LENGTH);
    root->hash = hex_new_hash;

    // Construct tree string
    tree.erase(tree.size() - 1, 1);
    tree.append("],\"links_num\":").append(to_string(root->links_num)).append(",");
    tree.append("\"hash\":\"").append(root->hash, HASH_LENGTH * 2).append("\",");
    tree.append("\"size\":").append(to_string(cur_size)).append("},");

    node_size += cur_size;


cleanup:

    free(sub_hashs);

    return crust_status;
}

/**
 * @description: Unseal file according to given path
 * @param p_dir -> Root directory path
 * @param dir_len -> Root dir path length
 * @param files -> Files in root directory
 * @param files_num -> Files number in root directory
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
    crust_status = persist_get((new_root_hash_str+"_meta").c_str(), &p_meta, &meta_len);
    if (CRUST_SUCCESS != crust_status || p_meta == NULL)
    {
        return CRUST_STORAGE_UNSEAL_FILE_FAILED;
    }
    std::string tree_meta(reinterpret_cast<char*>(p_meta), meta_len);
    json::JSON meta_json = json::JSON::Load(tree_meta);
    std::string new_dir(up_dir);
    new_dir.append("/").append(meta_json["old_hash"].ToString());
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
        new_path.append(dir).append("/").append(tag).append("_")
            .append(hexstring(new_hash, HASH_LENGTH), HASH_LENGTH * 2);
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
