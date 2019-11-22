#include "PlotDisk.h"

sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

std::vector<unsigned char *> all_g_hashs;

std::string get_file_path(const char *path, const size_t now_index)
{
    return std::string(path) + "/" + std::to_string(now_index + 1);
}

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

        /*
        eprintf("Hash %luM: '", i + 1);

        for (size_t j = 0; j < PLOT_HASH_LENGTH; j++)
        {
            eprintf("%02x", out_hash256[j]);
        }

        eprintf("'\n");
*/
        eprintf("EC data: '");

        for (size_t j = 0; j < PLOT_RAND_DATA_LENGTH; j++)
        {
            eprintf("%02x", rand_data[j]);
        }

        eprintf("'\n");
        

        size_t size_of_rand_data = sizeof(rand_data);
        size_t j = i + 1;
        ocall_save_file(dir_path.c_str(), out_hash256, &j, rand_data, &size_of_rand_data);
    }

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, PLOT_RAND_DATA_NUM * PLOT_HASH_LENGTH, &g_out_hash256);

    /*
    eprintf("Hash %luG: '", now_index + 1);
    for (size_t i = 0; i < PLOT_HASH_LENGTH; i++)
    {
        all_g_hashs[now_index][i] = g_out_hash256[i];
        eprintf("%02x", all_g_hashs[now_index][i]);
    }
    eprintf("'\n");
    */

    delete[] hashs;
}
