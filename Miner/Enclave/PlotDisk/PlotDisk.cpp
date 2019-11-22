#include "PlotDisk.h"

void ecall_plot_disk(const char *path)
{
    // New and get now G hash index
    sgx_thread_mutex_lock(&g_mutex);
    size_t now_index = all_g_hashs.size();
    eprintf("Now plot the %lu G\n", now_index + 1);
    all_g_hashs.push_back(new unsigned char[PLOT_HASH_LENGTH]);
    sgx_thread_mutex_unlock(&g_mutex);

    // Create directory
    std::string dir_path = get_file_path(path, now_index);
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

        save_file(dir_path.c_str(), i+1, out_hash256, rand_data, sizeof(rand_data));
    }

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH, &g_out_hash256);

    delete[] hashs;
}

std::string get_file_path(const char *path, const size_t now_index)
{
    return std::string(path) + "/" + std::to_string(now_index + 1);
}

void save_file(const char *dir_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size)
{
    std::string file_path(dir_path);
    std::string hex_string = unsigned_char_array_to_hex_string(hash, PLOT_HASH_LENGTH);
    file_path += '/' + std::to_string(index) + '-' + hex_string;
    eprintf("Into: %s\n", file_path.c_str());
}
