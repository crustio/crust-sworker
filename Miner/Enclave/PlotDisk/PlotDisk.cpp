#include "PlotDisk.h"


int a = 0;
sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

void ecall_plot_disk(const char *path, const size_t *size)
{
    eprintf("Enter num: %d\n", a);
    sgx_thread_mutex_lock(&g_mutex);
    a ++;
    sgx_thread_mutex_unlock(&g_mutex);
    
    for (size_t i = 0; i < *size; i++)
    {   
        eprintf("Now: %llu\n", i);
        unsigned char rand_data[RAND_DATA_LENGTH];
        sgx_read_rand(reinterpret_cast<unsigned char *>(&rand_data), sizeof(rand_data));
        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg(rand_data, sizeof(rand_data), &out_hash256);
    }
}
