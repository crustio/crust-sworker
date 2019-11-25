#include "PlotDisk.h"

void ecall_plot_disk(const char *path)
{
    // New and get now G hash index
    sgx_thread_mutex_lock(&g_mutex);
    size_t now_index = all_g_hashs.size();
    all_g_hashs.push_back(new unsigned char[PLOT_HASH_LENGTH]);
    sgx_thread_mutex_unlock(&g_mutex);

    // Create directory
    std::string dir_path = get_g_path(path, now_index);
    ocall_create_dir(dir_path.c_str());

    // Generate all M hashs and store file to disk
    unsigned char *hashs = new unsigned char[PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH];
    for (size_t i = 0; i < PLOT_RAND_DATA_NUM; i++)
    {
        unsigned char rand_data[PLOT_RAND_DATA_LENGTH];
        sgx_read_rand(reinterpret_cast<unsigned char *>(&rand_data), sizeof(rand_data));

        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg(rand_data, sizeof(rand_data), &out_hash256);

        for (size_t j = 0; j < PLOT_HASH_LENGTH; j++)
        {
            hashs[i * PLOT_HASH_LENGTH + j] = out_hash256[j];
        }

        save_file(dir_path.c_str(), i + 1, out_hash256, rand_data, sizeof(rand_data));
        eprintf("Save file: %luG/%luM\n", now_index + 1, i + 1);
    }

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(dir_path.c_str(), hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH);
    delete[] hashs;

    sgx_thread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < PLOT_HASH_LENGTH; i++)
    {
        all_g_hashs[now_index][i] = g_out_hash256[i];
    }
    sgx_thread_mutex_unlock(&g_mutex);

    // Change G path name
    std::string new_path = dir_path + '-' + unsigned_char_array_to_hex_string(g_out_hash256, PLOT_HASH_LENGTH);
    ocall_rename_dir(dir_path.c_str(), new_path.c_str());
}

void ecall_generate_root()
{
    unsigned char *hashs = new unsigned char[all_g_hashs.size() * PLOT_HASH_LENGTH];
    for (size_t i = 0; i < all_g_hashs.size(); i++)
    {
        for (size_t j = 0; j < PLOT_HASH_LENGTH; j++)
        {
            hashs[i * 32 + j] = all_g_hashs[i][j];
        }
    }

    empty_disk_capacity = all_g_hashs.size();
    sgx_sha256_msg(hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH, &root_hash);
    eprintf("Root hash: \n");
    for (size_t i = 0; i < PLOT_HASH_LENGTH; i++)
    {
        eprintf("%02x", root_hash[i]);
    }
    eprintf("\n");
    eprintf("Root capacity: %lu\n", empty_disk_capacity);
}

void ecall_validate_empty_disk(const char *path)
{
    size_t current_capacity = 0;
    ocall_get_folders_number_under_path(path, &current_capacity);

    /*    for (size_t i = all_g_hashs.size() - 1; i > current_capacity - 1; i--)
    {
        delete[] all_g_hashs[i];
        all_g_hashs.pop_back();
    }
    */

    for (size_t i = 0; i < (all_g_hashs.size() < current_capacity ? all_g_hashs.size() : current_capacity); i++)
    {
        unsigned char rand_val;
        sgx_read_rand((unsigned char *)&rand_val, 1);

        if (rand_val < 256 * VALIDATE_RATE)
        {
            unsigned char *m_hashs = NULL;
            ocall_get_file(&m_hashs, (get_g_path_with_hash(path, i, all_g_hashs[i]) + '/' + PLOT_M_HASHS).c_str(), PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH);

            if (m_hashs == NULL)
            {
                eprintf("\n!!!!USER CHEAT: BAD SUB M HASHS!!!!\n\n");
                return;
            }

            sgx_sha256_hash_t out_hash256;
            sgx_sha256_msg(m_hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH, &out_hash256);

            for (size_t j = 0; j < PLOT_HASH_LENGTH; j++)
            {
                if (all_g_hashs[i][j] != out_hash256[j])
                {
                    eprintf("\n!!!!USER CHEAT: WRONG G HASHS!!!!\n\n");
                    return;
                }
            }

            unsigned int rand_val_m;
            sgx_read_rand((unsigned char *)&rand_val_m, 4);
            size_t select = rand_val_m % PLOT_RAND_DATA_NUM;
        }
    }
}

std::string get_g_path_with_hash(const char *path, const size_t now_index, const unsigned char *hash)
{
    std::string g_path = std::string(path) + "/" + std::to_string(now_index + 1);
    return g_path + '-' + unsigned_char_array_to_hex_string(hash, PLOT_HASH_LENGTH);
}

std::string get_g_path(const char *path, const size_t now_index)
{
    return std::string(path) + "/" + std::to_string(now_index + 1);
}

void save_file(const char *dir_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size)
{
    std::string file_path(dir_path);
    std::string hash_hex_string = unsigned_char_array_to_hex_string(hash, PLOT_HASH_LENGTH);
    file_path += '/' + std::to_string(index) + '-' + hash_hex_string;
    ocall_save_file(file_path.c_str(), data, data_size);
}

void save_m_hashs_file(const char *dir_path, const unsigned char *data, size_t data_size)
{
    std::string file_path(dir_path);
    file_path = file_path + '/' + PLOT_M_HASHS;
    ocall_save_file(file_path.c_str(), data, data_size);
}
