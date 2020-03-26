#include "Validator.h"

extern sgx_thread_mutex_t g_workload_mutex;

/**
 * @description: validate empty disk
 * @param path -> the empty disk path
 */
void validate_empty_disk(const char *path)
{
    Workload *workload = get_workload();
    sgx_thread_mutex_lock(&g_workload_mutex);
    if (get_workload()->empty_disk_capacity == 0)
    {
        return;
    }
    sgx_thread_mutex_unlock(&g_workload_mutex);

    for (auto it_g_hash = workload->empty_g_hashs.begin(); it_g_hash != workload->empty_g_hashs.end(); it_g_hash++)
    {
        // Base info
        unsigned char *g_hash = (unsigned char *)malloc(HASH_LENGTH);
        std::string g_path;

        // For checking M hashs
        unsigned char *m_hashs_o = NULL;
        size_t m_hashs_size = 0;
        unsigned char *m_hashs = NULL;
        sgx_sha256_hash_t m_hashs_hash256;

        // For checking leaf
        unsigned int rand_val_m;
        size_t select = 0;
        std::string leaf_path;
        unsigned char *leaf_data = NULL;
        size_t leaf_data_len = 0;
        sgx_sha256_hash_t leaf_data_hash256;

        // Get g hash
        sgx_thread_mutex_lock(&g_workload_mutex);
        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            g_hash[j] = (*it_g_hash)[j];
        }

        if (is_null_hash(g_hash))
        {
            sgx_thread_mutex_unlock(&g_workload_mutex);
            goto end_validate_one_g_empty;
        }
        sgx_thread_mutex_unlock(&g_workload_mutex);
        g_path = get_g_path_with_hash(path, g_hash);

        // Get M hashs
        ocall_get_file(get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_o, &m_hashs_size);
        if (m_hashs_o == NULL)
        {
            cfeprintf("\n!!!!GET M HASHS FAILED!!!!\n");
            goto end_validate_one_g_empty_failed;
        }

        m_hashs = new unsigned char[m_hashs_size];
        for (size_t j = 0; j < m_hashs_size; j++)
        {
            m_hashs[j] = m_hashs_o[j];
        }

        /* Compare M hashs */
        sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_hash256);
        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            if (g_hash[j] != m_hashs_hash256[j])
            {
                cfeprintf("\n!!!!WRONG M HASHS!!!!\n");
                goto end_validate_one_g_empty_failed;
            }
        }

        /* Get leaf data */
        sgx_read_rand((unsigned char *)&rand_val_m, 4);
        select = rand_val_m % PLOT_RAND_DATA_NUM;
        leaf_path = get_leaf_path(g_path.c_str(), select, m_hashs + select * 32);
        ocall_get_file(leaf_path.c_str(), &leaf_data, &leaf_data_len);

        if (leaf_data == NULL)
        {
            cfeprintf("\n!!!!GET LEAF DATA FAILED!!!!\n");
            goto end_validate_one_g_empty_failed;
        }

        /* Compare leaf data */
        sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_data_hash256);

        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            if (m_hashs[select * 32 + j] != leaf_data_hash256[j])
            {
                cfeprintf("\n!!!!WRONG LEAF DATA HASHS!!!!\n");
                goto end_validate_one_g_empty_failed;
            }
        }

    goto end_validate_one_g_empty;
    end_validate_one_g_empty_failed:
        ocall_delete_folder_or_file(g_path.c_str());
        sgx_thread_mutex_lock(&g_workload_mutex);
        workload->empty_g_hashs.erase(it_g_hash);
        sgx_thread_mutex_unlock(&g_workload_mutex);
        it_g_hash--;

    end_validate_one_g_empty:
        if (g_hash != NULL)
        {
            free(g_hash);
        }
        if (m_hashs != NULL)
        {
            delete[] m_hashs;
        }
    }
}

/* Question: use files[i].cid will cause error. Files copy to envlave or files address copy to enclave? */
/**
 * @description: validate meaningful disk
 * @param files -> the changed files
 * @param files_num -> the number of changed files
 */
void validate_meaningful_disk(const Node *files, size_t files_num)
{
    /* Remove deleted files */
    Workload *workload = get_workload();
    for (size_t i = 0; i < files_num; i++)
    {
        if (files[i].exist == 0)
        {
            cfeprintf("Delete: Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_string(files[i].hash, HASH_LENGTH).c_str(), files[i].size);
            workload->files.erase(unsigned_char_array_to_unsigned_char_vector(files[i].hash, HASH_LENGTH));
        }
    }

    /* Validate old files */
    for (auto it = workload->files.begin(); it != workload->files.end(); it++)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);

        if (rand_val < 256 * MEANINGFUL_FILE_VALIDATE_RATE)
        {
            // Get merkle tree of file
            MerkleTree *tree = NULL;
            std::string root_hash = unsigned_char_array_to_hex_string(it->first.data(), HASH_LENGTH);
            ocall_get_merkle_tree(root_hash.c_str(), &tree);

            if (tree == NULL)
            {
                cfeprintf("\n!!!!USER CHEAT: CAN'T GET %s FILE!!!!\n", root_hash.c_str());
                return;
            }

            // Validate merkle tree
            size_t merkle_tree_size = 0;
            if (!validate_merkle_tree(tree, &merkle_tree_size) || merkle_tree_size != it->second)
            {
                cfeprintf("\n!!!!USER CHEAT: %s FILE IS NOT COMPLETED!!!!\n", root_hash.c_str());
                return;
            }
        }
    }

    /* Validate new files */
    for (size_t i = 0; i < files_num; i++)
    {
        if (files[i].exist != 0)
        {
            unsigned char rand_val;
            sgx_read_rand((unsigned char *)&rand_val, 1);

            if (rand_val < 256 * MEANINGFUL_FILE_VALIDATE_RATE)
            {
                // Get merkle tree of file
                MerkleTree *tree = NULL;
                std::string root_hash = unsigned_char_array_to_hex_string(files[i].hash, HASH_LENGTH);
                ocall_get_merkle_tree(root_hash.c_str(), &tree);

                if (tree == NULL)
                {
                    cfeprintf("\n!!!!USER CHEAT: CAN'T GET %s FILE!!!!\n", root_hash.c_str());
                    return;
                }

                // Validate merkle tree
                size_t merkle_tree_size = 0;
                if (!validate_merkle_tree(tree, &merkle_tree_size) || merkle_tree_size != files[i].size)
                {
                    cfeprintf("\n!!!!USER CHEAT: %s FILE IS NOT COMPLETED!!!!\n", root_hash.c_str());
                    return;
                }
            }

            cfeprintf("Add: Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_string(files[i].hash, HASH_LENGTH).c_str(), files[i].size);
            workload->files.insert(std::pair<std::vector<unsigned char>, size_t>(unsigned_char_array_to_unsigned_char_vector(files[i].hash, HASH_LENGTH), files[i].size));
        }
    }
}

/**
 * @description: validate merkle tree recursively
 * @param root -> the root of merkle tree
 * @param size(out) -> used for statistics merkle tree size
 */
bool validate_merkle_tree(MerkleTree *root, size_t *size)
{
    if (root == NULL)
    {
        return true;
    }

    size_t block_size = 0;
    unsigned char *block_data = NULL;
    unsigned char rand_val;
    sgx_read_rand((unsigned char *)&rand_val, 1);

    /* Validate block data */
    if (rand_val < 256 * MEANINGFUL_BLOCK_VALIDATE_RATE)
    {
        ocall_get_block(std::string(root->hash).c_str(), &block_size, &block_data);
        if (block_data == NULL || block_size != root->size)
        {
            return false;
        }
        else
        {
            sgx_sha256_hash_t block_data_hash256;
            sgx_sha256_msg(block_data, (uint32_t)block_size, &block_data_hash256);

            std::string block_data_hash256_string = unsigned_char_array_to_hex_string(block_data_hash256, HASH_LENGTH);
            if (strcmp(root->hash, block_data_hash256_string.c_str()))
            {
                return false;
            }
        }
    }

    if (root->links != NULL)
    {
        /* Get all links from block data and compare links */
        if (block_size != 0)
        {
            std::vector<std::string> hashs = get_hashs_from_block(block_data, block_size);
            if (hashs.size() != root->links_num)
            {
                return false;
            }

            for (size_t i = 0; i < hashs.size(); i++)
            {
                if (hashs[i] != root->links[i]->hash)
                {
                    return false;
                }
            }
        }

        /* Validate links recursively*/
        for (size_t i = 0; i < root->links_num; i++)
        {
            if (!validate_merkle_tree(root->links[i], size))
            {
                return false;
            }
        }
    }

    *size += root->size;
    return true;
}

/**
 * @description: get all links' hash from block
 * @param block_data -> the block data
 * @param block_size -> the size of block data
 */
std::vector<std::string> get_hashs_from_block(unsigned char *block_data, size_t block_size)
{
    std::vector<std::string> hashs;
    if (block_data == NULL)
    {
        return hashs;
    }

    std::string block_data_str = unsigned_char_array_to_hex_string(block_data, block_size);

    std::string flag = "0a221220";
    size_t position = 0;

    while ((position = block_data_str.find(flag, position)) != std::string::npos)
    {
        hashs.push_back(block_data_str.substr(position + flag.length(), HASH_LENGTH * 2));
        position += flag.length() + HASH_LENGTH * 2;
    }

    return hashs;
}
