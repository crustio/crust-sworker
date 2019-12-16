#include "Validator.h"

void validate_empty_disk(const char *path)
{
    Workload *workload = get_workload();
    size_t current_capacity = 0;
    ocall_get_folders_number_under_path(&current_capacity, path);

    for (size_t i = 0; i < (workload->empty_g_hashs.size() < current_capacity ? workload->empty_g_hashs.size() : current_capacity); i++)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);

        if (rand_val < 256 * EMPTY_VALIDATE_RATE)
        {
            // Get m hashs
            unsigned char *m_hashs = NULL;
            std::string g_path = get_g_path_with_hash(path, i, workload->empty_g_hashs[i]);
            ocall_get_file(&m_hashs, get_m_hashs_file_path(g_path.c_str()).c_str(), PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH);

            if (m_hashs == NULL)
            {
                eprintf("\n!!!!USER CHEAT: GET M HASHS FAILED!!!!\n");
                return;
            }

            // Compare m hashs
            sgx_sha256_hash_t m_hashs_hash256;
            sgx_sha256_msg(m_hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH, &m_hashs_hash256);

            for (size_t j = 0; j < PLOT_HASH_LENGTH; j++)
            {
                if (workload->empty_g_hashs[i][j] != m_hashs_hash256[j])
                {
                    eprintf("\n!!!!USER CHEAT: WRONG M HASHS!!!!\n");
                    return;
                }
            }

            // Get leaf data
            unsigned int rand_val_m;
            sgx_read_rand((unsigned char *)&rand_val_m, 4);
            size_t select = rand_val_m % PLOT_RAND_DATA_NUM;
            std::string leaf_path = get_leaf_path(g_path.c_str(), select, m_hashs + select * 32);
            // eprintf("Select path: %s\n", leaf_path.c_str());

            unsigned char *leaf_data = NULL;
            ocall_get_file(&leaf_data, leaf_path.c_str(), PLOT_RAND_DATA_LENGTH);

            if (leaf_data == NULL)
            {
                eprintf("\n!!!!USER CHEAT: GET LEAF DATA FAILED!!!!\n");
                return;
            }

            // Compare leaf data
            sgx_sha256_hash_t leaf_data_hash256;
            sgx_sha256_msg(leaf_data, PLOT_RAND_DATA_LENGTH, &leaf_data_hash256);

            for (size_t j = 0; j < PLOT_HASH_LENGTH; j++)
            {
                if (m_hashs[select * 32 + j] != leaf_data_hash256[j])
                {
                    eprintf("\n!!!!USER CHEAT: WRONG LEAF DATA HASHS!!!!\n");
                    return;
                }
            }
        }
    }

    for (size_t i = workload->empty_g_hashs.size() - 1; i > current_capacity - 1; i--)
    {
        delete[] workload->empty_g_hashs[i];
        workload->empty_g_hashs.pop_back();
    }

    ecall_generate_empty_root();
}

// Question: use files[i].cid will cause error. Files copy to envlave or files address copy to enclave?
void validate_meaningful_disk(const Node *files, size_t files_num)
{
    Workload *workload = get_workload();

    for (size_t i = 0; i < files_num; i++)
    {
        if (files[i].exist == 0)
        {
            eprintf("Delete: Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_string(files[i].hash, PLOT_HASH_LENGTH).c_str(), files[i].size);
            workload->files.erase(unsigned_char_array_to_unsigned_char_vector(files[i].hash, PLOT_HASH_LENGTH));
        }
        else
        {
            eprintf("Add: Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_string(files[i].hash, PLOT_HASH_LENGTH).c_str(), files[i].size);
            workload->files.insert(std::pair<std::vector<unsigned char>, size_t>(unsigned_char_array_to_unsigned_char_vector(files[i].hash, PLOT_HASH_LENGTH), files[i].size));
        }
    }

    for (auto it = workload->files.begin(); it != workload->files.end(); it++)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);

        if (rand_val < 256 * MEANINGFUL_FILE_VALIDATE_RATE)
        {
            MerkleTree *tree = NULL;
            std::string root_hash = unsigned_char_array_to_hex_string(it->first.data(), PLOT_HASH_LENGTH);
            ocall_get_merkle_tree(&tree, root_hash.c_str());

            if (tree == NULL)
            {
                eprintf("\n!!!!USER CHEAT: CAN'T GET %s FILE!!!!\n", root_hash.c_str());
                return;
            }

            size_t merkle_tree_size = 0;
            if (!validate_merkle_tree(tree, &merkle_tree_size) || merkle_tree_size != it->second)
            {
                eprintf("\n!!!!USER CHEAT: %s FILE IS NOT COMPLETED!!!!\n", root_hash.c_str());
                return;
            }
        }
    }
}

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

    if (rand_val < 256 * MEANINGFUL_BLOCK_VALIDATE_RATE)
    {
        ocall_get_block(&block_data, std::string(root->hash).c_str(), &block_size);
        if (block_data == NULL || block_size != root->size)
        {
            return false;
        }
        else
        {
            sgx_sha256_hash_t block_data_hash256;
            sgx_sha256_msg(block_data, (uint32_t)block_size, &block_data_hash256);

            std::string block_data_hash256_string = unsigned_char_array_to_hex_string(block_data_hash256, PLOT_HASH_LENGTH);
            if (strcmp(root->hash, block_data_hash256_string.c_str()))
            {
                return false;
            }
        }
    }

    if (root->links != NULL)
    {
        if (block_size != 0)
        {
            std::vector<std::string> hashs = get_hashs_from_block(block_data, block_size);
            if (hashs.size() !=  root->links_num)
            {
                return false;
            }

            for (size_t i = 0; i < hashs.size(); i++)
            {
                if(hashs[i] != root->links[i]->hash)
                {
                    return false;
                }
            }
        }

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
        hashs.push_back(block_data_str.substr(position + flag.length(), PLOT_HASH_LENGTH * 2));
        position += flag.length() + PLOT_HASH_LENGTH * 2;
    }
    
    return hashs;
}
