#include "Validator.h"

bool validate_merkle_tree(MerkleTree *root, size_t *size);

void ecall_validate_empty_disk(const char *path)
{
    Workload *workload = get_workload();
    size_t current_capacity = 0;
    ocall_get_folders_number_under_path(path, &current_capacity);

    for (size_t i = 0; i < (workload->all_g_hashs.size() < current_capacity ? workload->all_g_hashs.size() : current_capacity); i++)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);

        if (rand_val < 256 * EMPTY_VALIDATE_RATE)
        {
            // Get m hashs
            unsigned char *m_hashs = NULL;
            std::string g_path = get_g_path_with_hash(path, i, workload->all_g_hashs[i]);
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
                if (workload->all_g_hashs[i][j] != m_hashs_hash256[j])
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
            eprintf("Select path: %s\n", leaf_path.c_str());

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

    for (size_t i = workload->all_g_hashs.size() - 1; i > current_capacity - 1; i--)
    {
        delete[] workload->all_g_hashs[i];
        workload->all_g_hashs.pop_back();
    }

    ecall_generate_root();
}

void ecall_validate_meaningful_disk(const Node *files, size_t files_num, size_t files_space_size)
{
    (void)(files_space_size);

    for (size_t i = 0; i < files_num; i++)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);

        if (rand_val < 256 * MEANINGFUL_FILE_VALIDATE_RATE)
        {
            MerkleTree *tree = NULL;
            // Question: use files[i].cid will cause error. Files copy to envlave or files address copy to enclave?
            ocall_get_merkle_tree(&tree, std::string(files[i].cid).c_str());

            if (tree == NULL)
            {
                eprintf("\n!!!!USER CHEAT: CAN'T GET %s FILE!!!!\n", files[i].cid);
                return;
            }

            size_t merkle_tree_size = 0;
            if (!validate_merkle_tree(tree, &merkle_tree_size) || merkle_tree_size != files[i].size)
            {
                eprintf("\n!!!!USER CHEAT: %s FILE IS NOT COMPLETED!!!!\n", files[i].cid);
                return;
            }
        }
    }

    eprintf("Total work is \n");
    for (size_t i = 0; i < files_num; i++)
    {
        eprintf("   File%lu: cid->%s, size->%lu\n", i + 1, files[i].cid, files[i].size);
    }
}

bool validate_merkle_tree(MerkleTree *root, size_t *size)
{
    if (root == NULL)
    {
        return true;
    }

    if (root->links == NULL)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);
        if (rand_val < 256 * MEANINGFUL_LEAF_VALIDATE_RATE)
        {
            size_t block_size = 0;
            unsigned char *block_data = NULL;
            ocall_get_block(&block_data, std::string(root->cid).c_str(), &block_size);
            if (block_data == NULL || block_size != root->size)
            {
                return false;
            }
            else
            {
                sgx_sha256_hash_t block_data_hash256;
                sgx_sha256_msg(block_data, (uint32_t)block_size, &block_data_hash256);
                *size += block_size;
                return is_cid_equal_hash(root->cid, block_data_hash256);
            }
        }

        *size += root->size;
    }
    else
    {
        // TODO: validate path
        *size += root->size;
        for (size_t i = 0; i < root->links_num; i++)
        {
            if (!validate_merkle_tree(root->links[i], size))
            {
                return false;
            }
        }
    }

    return true;
}
