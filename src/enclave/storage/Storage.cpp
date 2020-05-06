#include "Storage.h"
#include "EUtils.h"
#include "Persistence.h"

using namespace std;

// Old tree root hash to pair which consists of serialized old tree and leaf position and total size
map<vector<uint8_t>, tuple<string,size_t,size_t>> tree_meta_map;
// Map used to store sealed tree root to sealed tree root node
map<vector<uint8_t>, MerkleTree *> new_tree_map;
// Lock used to lock outside buffer
sgx_thread_mutex_t g_file_buffer_mutex;

// Current node public and private key pair
extern ecc_key_pair id_key_pair;

crust_status_t _validate_meaningful_data(MerkleTree *root, MerkleTree *cur_node, vector<uint32_t> path);
crust_status_t _storage_seal_file(MerkleTree *root, string path, string &tree, size_t &total_sealed_data_size);
void _gen_validated_merkle_tree(MerkleTree *tree);

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
    string ser_tree = storage_ser_merkle_tree(root);
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
crust_status_t storage_seal_file(MerkleTree *root, const char *path, size_t path_len)
{
    std::string org_root_hash_str(root->hash, HASH_LENGTH * 2);
    std::string old_path(path, path_len);
    std::string new_tree;

    // Do seal file
    size_t total_sealed_data_size = 0;
    crust_status_t crust_status = _storage_seal_file(root, old_path, new_tree, total_sealed_data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    std::string new_root_hash_str(root->hash, HASH_LENGTH * 2);

    // Store new tree structure
    std::string new_tree_meta_data;
    new_tree_meta_data.append(new_tree);
    new_tree_meta_data.append(CRUST_SEPARATOR).append(org_root_hash_str).append("_hash");
    new_tree_meta_data.append(CRUST_SEPARATOR).append(to_string(total_sealed_data_size));
    crust_status = persist_add(new_root_hash_str.c_str(), (const uint8_t*)new_tree_meta_data.c_str(), new_tree_meta_data.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Store new root hash to old root hash mapping
    crust_status = persist_add((new_root_hash_str+"_hash").c_str(), (const uint8_t*)org_root_hash_str.c_str(), org_root_hash_str.size());
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Pass new tree structure to APP
    ocall_store_sealed_merkletree(org_root_hash_str.c_str(), new_tree.c_str(), new_tree.size());

    // Rename old directory
    std::string new_path = old_path.substr(0, old_path.find(org_root_hash_str)) + new_root_hash_str;
    ocall_rename_dir(&crust_status, old_path.c_str(), new_path.c_str());

    return crust_status;
}

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param root -> MerkleTree root node
 * @param path -> Reference to file path
 * @param tree -> New MerkleTree
 * @return: Seal status
 * */
crust_status_t _storage_seal_file(MerkleTree *root, string path, string &tree, size_t &total_sealed_data_size)
{
    if (root == NULL)
        return CRUST_SUCCESS;

    crust_status_t crust_status = CRUST_SUCCESS;

    // ----- Deal with leaf node ----- //
    if (root->links_num == 0)
    {
        std::string old_path;
        std::string old_hash_str = std::string(root->hash);
        size_t s_pos = old_hash_str.find("_");
        if (s_pos == old_hash_str.npos)
        {
            return CRUST_INVALID_MERKLETREE;
        }
        std::string tag = old_hash_str.substr(0, s_pos);
        old_path.append(path).append("/").append(old_hash_str);

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
        new_path.append(path).append("/").append(tag).append("_").append(hex_new_hash, HASH_LENGTH * 2);
        // Replace old file with new file
        ocall_replace_file(&crust_status, old_path.c_str(), new_path.c_str(), p_sealed_data, sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto sealend;
        }
        root->hash = hex_new_hash;
        total_sealed_data_size += sealed_data_size;

        // Construct tree string
        tree.append("{\"hash\":\"").append(tag).append("_").append(root->hash, HASH_LENGTH * 2).append("\",");
        tree.append("\"links_num\":").append(to_string(root->links_num)).append("},");

    sealend:

        if (file_data_r != NULL)
            free(file_data_r);

        if (p_sealed_data != NULL)
            free(p_sealed_data);

        return crust_status;
    }

    // ----- Deal with non-leaf node ----- //
    // Construct tree string
    tree.append("{\"links_num\":").append(to_string(root->links_num)).append(",");
    tree.append("\"links\": [");

    size_t sub_hashs_len = root->links_num * HASH_LENGTH;
    uint8_t *sub_hashs = (uint8_t*)malloc(sub_hashs_len);
    memset(sub_hashs, 0, sub_hashs_len);
    char *hex_new_hash = NULL;
    for (size_t i = 0; i < root->links_num; i++)
    {
        crust_status = _storage_seal_file(root->links[i], path, tree, total_sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            goto cleanup;
        }
        memcpy(sub_hashs + i * HASH_LENGTH, root->links[i]->hash, HASH_LENGTH);
    }
    // Get new hash
    sgx_sha256_hash_t new_hash;
    sgx_sha256_msg(sub_hashs, sub_hashs_len, &new_hash);
    hex_new_hash = hexstring(new_hash, HASH_LENGTH);
    root->hash = reinterpret_cast<char*>(hex_new_hash);

    // Construct tree string
    tree.erase(tree.size() - 1, 1);
    tree.append("],\"hash\":\"").append(root->hash, HASH_LENGTH * 2).append("\"},");


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
crust_status_t storage_unseal_file(char **files, size_t files_num, const char *p_dir)
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
    uint8_t *p_old_hash = NULL;
    size_t old_hash_len;
    crust_status = persist_get((new_root_hash_str+"_hash").c_str(), &p_old_hash, &old_hash_len);
    if (CRUST_SUCCESS != crust_status || p_old_hash == NULL)
    {
        return CRUST_STORAGE_UNSEAL_FILE_FAILED;
    }
    std::string old_root_hash_str(reinterpret_cast<char*>(p_old_hash), old_hash_len);
    std::string new_dir(up_dir);
    new_dir.append("/").append(old_root_hash_str);
    free(p_old_hash);
    
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


cleanup:

    if (p_sealed_data_r != NULL)
        free(p_sealed_data_r);

    if (p_decrypted_data != NULL)
        free(p_decrypted_data);

    return crust_status;
}

/**
 * @description: Seal file block and generate new tree
 * @param root_hash -> file root hash
 * @param root_hash_len -> file root hash lenght
 * @param p_src -> pointer to file block data
 * @param src_len -> file block data size
 * @param p_sealed_data -> sealed file block data
 * @param sealed_data_size -> sealed file block data size
 * @return: Seal and generate result
 * */
crust_status_t storage_seal_data(const uint8_t *root_hash, uint32_t root_hash_len,
        const uint8_t *p_src, size_t src_len, uint8_t *p_sealed_data, size_t sealed_data_size)
{
    // ----- Get merkle tree metadata ----- //
    vector<uint8_t> root_hash_v(root_hash, root_hash + root_hash_len);

    if (tree_meta_map.find(root_hash_v) == tree_meta_map.end())
    {
        return CRUST_NOTFOUND_MERKLETREE;
    }
    auto entry = tree_meta_map[root_hash_v];

    // ----- Verify file block hash ----- //
    sgx_sha256_hash_t cur_hash;
    sgx_sha256_msg(p_src, src_len, &cur_hash);

    string ser_tree = std::get<0>(entry);
    size_t spos = std::get<1>(entry);
    if (spos == std::string::npos)
    {
        return CRUST_DUPLICATED_SEAL;
    }
    spos += strlen(LEAF_SEPARATOR);
    size_t file_size = std::get<2>(entry);
    uint8_t *org_hash = hex_string_to_bytes(ser_tree.substr(spos, HASH_LENGTH * 2).c_str(), HASH_LENGTH * 2);
    // Compare hash value
    for (size_t i = 0; i < root_hash_len; i++)
    {
        if (org_hash[i] != cur_hash[i])
        {
            return CRUST_WRONG_FILE_BLOCK;
        }
    }
    free(org_hash);
    
    // ----- Seal original file block ----- //
    uint32_t pri_key_len = sizeof(id_key_pair.pri_key);
    uint32_t src_r_len = sizeof(uint32_t) * 2 + src_len + pri_key_len;
    uint8_t *p_src_r = (uint8_t*)malloc(src_r_len);
    uint8_t *pp = p_src_r;
    memset(p_src_r, 0, src_r_len);
    // Get source data
    memcpy(pp, &src_len, sizeof(uint32_t));
    pp += sizeof(uint32_t);
    memcpy(pp, &pri_key_len, sizeof(uint32_t));
    pp += sizeof(uint32_t);
    memcpy(pp, p_src, src_len);
    pp += src_len;
    memcpy(pp, &id_key_pair.pri_key, sizeof(id_key_pair.pri_key));

    // Get sealed data
    uint8_t *p_sealed_data_r = NULL;
    crust_status_t crust_status = seal_data_mrenclave(p_src_r, src_r_len, 
            (sgx_sealed_data_t**)&p_sealed_data_r, &sealed_data_size);

    // Free tmp buffer
    free(p_src_r);

    if (CRUST_SUCCESS != crust_status || p_sealed_data_r == NULL)
    {
        return CRUST_SEAL_DATA_FAILED;
    }
    memcpy(p_sealed_data, p_sealed_data_r, sealed_data_size);

    // ----- Set new metadata ----- //
    sgx_sha256_hash_t cur_new_hash;
    sgx_sha256_msg(p_sealed_data_r, sealed_data_size, &cur_new_hash);
    const char *p_new_hash_hex = hexstring(&cur_new_hash, HASH_LENGTH);
    // Set new node hash
    for (int i = 0; i < HASH_LENGTH * 2; i++)
    {
        ser_tree[i + spos] = p_new_hash_hex[i];
    }
    // Set new start position
    spos = ser_tree.find(LEAF_SEPARATOR, spos);
    tree_meta_map[root_hash_v] = make_tuple(ser_tree, spos, file_size + sealed_data_size);


    free(p_sealed_data_r);

    return CRUST_SUCCESS;
}

/**
 * @description: Unseal and verify file block data
 * @param p_sealed_data -> sealed file block data
 * @param sealed_data_size -> sealed file block data size
 * @param p_unsealed_data -> unsealed file block data
 * @param unsealed_data_size -> unsealed file block data size
 * @return: Unseal status
 * */
crust_status_t storage_unseal_data(const uint8_t *p_sealed_data, size_t sealed_data_size,
        uint8_t *p_unsealed_data, uint32_t unsealed_data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    uint8_t *p_unsealed_pri_key = NULL;
    uint32_t src_len = 0;
    uint32_t pri_key_len = 0;

    // ----- Unseal file block ----- //
    // Create buffer in enclave
    sgx_sealed_data_t *p_sealed_data_r = (sgx_sealed_data_t *)malloc(sealed_data_size);
    memset(p_sealed_data_r, 0, sealed_data_size);
    memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
    // Create buffer for decrypted data
    uint32_t decrypted_data_len = sgx_get_encrypt_txt_len(p_sealed_data_r);
    uint8_t *p_decrypted_data = (uint8_t *)malloc(decrypted_data_len);
    sgx_status = sgx_unseal_data(p_sealed_data_r, NULL, NULL,
            p_decrypted_data, &decrypted_data_len);
    if (SGX_SUCCESS != sgx_status)
    {
        log_err("Unseal data failed!Error code:%lx\n", sgx_status);
        crust_status = CRUST_UNSEAL_DATA_FAILED;
        goto cleanup;
    }

    // Check if data is private data
    if (memcmp(p_decrypted_data, TEE_PRIVATE_TAG, strlen(TEE_PRIVATE_TAG)) == 0)
    {
        crust_status = CRUST_MALWARE_DATA_BLOCK;
        goto cleanup;
    }

    // ----- Deserialize file block related data ----- //
    memcpy(&src_len, p_decrypted_data, sizeof(uint32_t));
    if (src_len != unsealed_data_size)
    {
        crust_status = CRUST_MALWARE_DATA_BLOCK;
        goto cleanup;
    }
    p_decrypted_data += sizeof(uint32_t);
    memcpy(&pri_key_len, p_decrypted_data, sizeof(uint32_t));
    p_decrypted_data += sizeof(uint32_t);
    // Verify unsealed data
    memcpy(p_unsealed_data, p_decrypted_data, src_len);
    p_decrypted_data += src_len;
    // Compare if the private key belongs to current tee
    p_unsealed_pri_key = (uint8_t *)malloc(pri_key_len);
    memset(p_unsealed_pri_key, 0, pri_key_len);
    memcpy(p_unsealed_pri_key, p_decrypted_data, pri_key_len);
    if (memcmp(p_unsealed_pri_key, &id_key_pair.pri_key, pri_key_len) != 0)
    {
        crust_status = CRUST_MALWARE_DATA_BLOCK;
        goto cleanup;
    }

cleanup:

    free(p_decrypted_data);

    return crust_status;
}

/**
 * @description: Generate validate Merkle hash tree after seal file successfully
 * @param root_hash -> root hash of Merkle tree
 * @param root_hash_len -> root hash length
 * @return: Generate status
 * */
crust_status_t storage_gen_new_merkle_tree(const uint8_t *root_hash, uint32_t root_hash_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    // Get sealed complete tree metadata
    vector<uint8_t> root_hash_v(root_hash, root_hash + root_hash_len);
    if (tree_meta_map.find(root_hash_v) == tree_meta_map.end())
    {
        return CRUST_NOTFOUND_MERKLETREE;
    }

    // Judge whether seal has been completed
    auto entry = tree_meta_map[root_hash_v];
    string ser_tree = std::get<0>(entry);
    size_t spos = std::get<1>(entry);
    if (spos != string::npos)
    {
        return CRUST_SEAL_NOTCOMPLETE;
    }
    // Deserialize tree
    MerkleTree *new_root = NULL;
    spos = 0;
    if (CRUST_SUCCESS != (crust_status = storage_deser_merkle_tree(&new_root, ser_tree, spos)) || new_root == NULL)
    {
        log_err("[enclave] Deserialize MerkleTree failed!Error code:%lx\n", crust_status);
        return CRUST_DESER_MERKLE_TREE_FAILED;
    }

    // Get sealed tree
    _gen_validated_merkle_tree(new_root);
    vector<uint8_t> new_root_hash_v(new_root->hash, new_root->hash + HASH_LENGTH);
    new_tree_map[new_root_hash_v] = new_root;

    // For log
    string new_ser_tree = storage_ser_merkle_tree(new_root);
    log_info("new tree string:%s\n", new_ser_tree.c_str());

    return CRUST_SUCCESS;
}

/**
 * @description: Transfer a Merkle tree to valid hash tree
 * @param tree -> Pointer to Merkle tree root node
 * */
void _gen_validated_merkle_tree(MerkleTree *tree)
{
    if (tree == NULL || tree->links_num == 0)
    {
        return;
    }

    uint8_t *g_hashs = (uint8_t*)malloc(tree->links_num * HASH_LENGTH);
    for (uint32_t i = 0; i < tree->links_num; i++)
    {
        _gen_validated_merkle_tree(tree->links[i]);
        memcpy(g_hashs + i * HASH_LENGTH, tree->links[i]->hash, HASH_LENGTH);
    }

    sgx_sha256_hash_t g_hashs_hash256;
    sgx_sha256_msg(g_hashs, tree->links_num * HASH_LENGTH, &g_hashs_hash256);

    free(g_hashs);

    tree->hash = (char*)malloc(HASH_LENGTH);
    memset(tree->hash, 0, HASH_LENGTH);
    memcpy(tree->hash, g_hashs_hash256, HASH_LENGTH);
}

/**
 * @description: Validate meaningful data
 * @return: Validate result
 * */
crust_status_t storage_validate_meaningful_data()
{
    unsigned char rand_val;
    for (auto it : new_tree_map)
    {
        sgx_read_rand((unsigned char *)&rand_val, 1);
        if (rand_val % 2 == 0)
        {
            MerkleTree *root = it.second;
            vector<uint32_t> path_v;
            if (CRUST_SUCCESS != _validate_meaningful_data(root, root, path_v))
            {
                return CRUST_VERIFY_MEANINGFUL_FAILED;
            }
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Real validate meaningful data function
 * @param root -> To be validated merkle tree root node
 * @param cur_node -> Validating merkle tree node
 * @param path -> Path from root node to leaf node
 * @return: Validate result
 * */
crust_status_t _validate_meaningful_data(MerkleTree *root, MerkleTree *cur_node, vector<uint32_t> path)
{
    if (cur_node == NULL)
    {
        return CRUST_SUCCESS;
    }

    // Validate leaf node hash value
    if (cur_node->links_num == 0)
    {
        char *cur_hash = (char*)malloc(HASH_LENGTH);
        crust_status_t crust_status = CRUST_SUCCESS;
        ocall_get_file_block_by_path(&crust_status, root->hash, cur_hash, HASH_LENGTH, path.data(), path.size());
        if (CRUST_SUCCESS != crust_status)
        {
            return CRUST_GET_FILE_BLOCK_FAILED;
        }
        if (memcmp(cur_hash, cur_node->hash, HASH_LENGTH) != 0)
        {
            return CRUST_INVALID_SEALED_DATA;
        }
    }

    // Validate file block recursively
    unsigned char rand_val;
    set<uint32_t> validated_idx;
    for (int i = 0; i < 3; i++)
    {
        sgx_read_rand((unsigned char *)&rand_val, 1);
        uint32_t idx = rand_val % cur_node->links_num;
        if (validated_idx.find(idx) != validated_idx.end())
        {
            continue;
        }
        path.push_back(idx);
        if (CRUST_SUCCESS != _validate_meaningful_data(root, cur_node->links[idx], path))
        {
            return CRUST_INVALID_SEALED_DATA;
        }
        path.pop_back();
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Serialize Merkle tree
 * @param tree -> root of Merkle tree
 * @return: Serialized string
 * */
string storage_ser_merkle_tree(MerkleTree *tree)
{
    if (tree == NULL)
    {
        return "";
    }

    std::string ans;

    string hex_str(hexstring(tree->hash, HASH_LENGTH), HASH_LENGTH * 2);

    if (tree->links_num == 0)
    {
        ans.append(LEAF_SEPARATOR).append(hex_str);
    }
    else
    {
        ans.append(hex_str);
    }

    ans.append("{")
       .append(to_string(tree->size))
       .append(",")
       .append(to_string(tree->links_num))
       .append(",");

    if (tree->links_num != 0)
    {
        for (size_t i = 0; i < tree->links_num; i++)
        {
            ans.append(storage_ser_merkle_tree(tree->links[i]))
               .append(",");
        }
    }

    ans.append("}");

    return ans;
}

/**
 * @description: Deserialize Merkle tree
 * @param root -> root of Merkle tree
 * @param ser_tree -> serialized Merkle tree
 * @param spos -> start position of deserialized string
 * @return: Root value of Merkle tree
 * */
crust_status_t storage_deser_merkle_tree(MerkleTree **root, string ser_tree, size_t &spos)
{
    if (spos >= ser_tree.size())
    {
        return CRUST_SUCCESS;
    }

    *root = new MerkleTree();
    MerkleTree *p_root = *root;

    // Get hash
    size_t epos = ser_tree.find("{", spos);
    string hash = ser_tree.substr(spos, epos - spos);
    if (hash.find(LEAF_SEPARATOR) != string::npos)
    {
        hash = hash.substr(hash.find(LEAF_SEPARATOR) + strlen(LEAF_SEPARATOR), HASH_LENGTH * 2);
    }

    p_root->hash = (char*)hex_string_to_bytes(hash.c_str(), hash.size());

    // Get size
    spos = epos + 1;
    epos = ser_tree.find(",", spos);
    if (epos < spos)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    size_t size = atoi(ser_tree.substr(spos, epos - spos).c_str());
    p_root->size = size;

    // Get links_num
    spos = epos + 1;
    epos = ser_tree.find(",", spos);
    if (epos < spos)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    size_t links_num = atoi(ser_tree.substr(spos, epos - spos).c_str());
    p_root->links_num = links_num;

    // Get children nodes
    spos = epos + 1;
    if (p_root->links_num != 0)
    {
        p_root->links = (MerkleTree**)malloc(p_root->links_num * sizeof(MerkleTree*));
    }
    else
    {
        while (spos < ser_tree.size() && (ser_tree[spos] == '}' || ser_tree[spos] == ',')) spos++;
        return CRUST_SUCCESS;
    }

    // Deserialize merkle tree recursively
    for (size_t i = 0; i < p_root->links_num; i++)
    {
        MerkleTree *child = NULL;
        storage_deser_merkle_tree(&child, ser_tree, spos);
        p_root->links[i] = child;
    }

    return CRUST_SUCCESS;
}
