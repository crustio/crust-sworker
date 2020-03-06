#include "PlotDisk.h"

// TODO: put log to file
/* Used to update workload->empty_g_hashs multiple threads */
sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

/**
 * @description: plot one G disk under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void ecall_plot_disk(const char *path)
{
    /* New and get now G hash index */
    sgx_thread_mutex_lock(&g_mutex);
    size_t now_index = get_workload()->empty_g_hashs.size();
    get_workload()->empty_g_hashs.push_back((uint8_t*)malloc(HASH_LENGTH));
    sgx_thread_mutex_unlock(&g_mutex);

    /* Create directory */
    std::string g_path = get_g_path(path, now_index);
    ocall_create_dir(g_path.c_str());

    /* Generate all M hashs and store file to disk */
    unsigned char *hashs = new unsigned char[PLOT_RAND_DATA_NUM * HASH_LENGTH];
    for (size_t i = 0; i < PLOT_RAND_DATA_NUM; i++)
    {
        unsigned char rand_data[PLOT_RAND_DATA_LENGTH];
        sgx_read_rand(reinterpret_cast<unsigned char *>(&rand_data), sizeof(rand_data));

        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg(rand_data, sizeof(rand_data), &out_hash256);

        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            hashs[i * HASH_LENGTH + j] = out_hash256[j];
        }

        save_file(g_path.c_str(), i, out_hash256, rand_data, sizeof(rand_data));

        if ((i + 1) == 1 || (i + 1) % 100 == 0 || (i + 1) == PLOT_RAND_DATA_NUM)
        {
            cfeprintf("Plot file: %luG/%luM success\n", now_index + 1, i + 1);
        }
    }

    /* Generate G hashs */
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, PLOT_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(g_path.c_str(), hashs, PLOT_RAND_DATA_NUM * HASH_LENGTH);
    delete[] hashs;

    sgx_thread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < HASH_LENGTH; i++)
    {
        get_workload()->empty_g_hashs[now_index][i] = g_out_hash256[i];
    }
    sgx_thread_mutex_unlock(&g_mutex);

    /* Change G path name */
    std::string new_g_path = g_path + '-' + unsigned_char_array_to_hex_string(g_out_hash256, HASH_LENGTH);
    ocall_rename_dir(g_path.c_str(), new_g_path.c_str());
}

/**
 * @description: generate empty root hash by using workload->empty_g_hashs 
 */
void ecall_generate_empty_root(void)
{
    if (get_workload()->empty_g_hashs.size() == 0)
    {
        get_workload()->empty_disk_capacity = 0;
        get_workload()->empty_root_hash[0] = 0;
        return;
    }

    unsigned char *hashs = (unsigned char*)malloc(get_workload()->empty_g_hashs.size() * HASH_LENGTH);
    for (size_t i = 0; i < get_workload()->empty_g_hashs.size(); i++)
    {
        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            hashs[i * 32 + j] = get_workload()->empty_g_hashs[i][j];
        }
    }

    get_workload()->empty_disk_capacity = get_workload()->empty_g_hashs.size();
    sgx_sha256_msg(hashs, (uint32_t)get_workload()->empty_disk_capacity * HASH_LENGTH, &get_workload()->empty_root_hash);

    delete[] hashs;
}

/**
 * @description: call ocall_save_file to save file
 * @param g_path -> g folder path
 * @param index -> m file's index
 * @param hash -> m file's hash
 * @param data -> m file's data
 * @param data_size -> the length of m file's data
 */
void save_file(const char *g_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_leaf_path(g_path, index, hash);
    ocall_save_file(file_path.c_str(), data, data_size);
}

/**
 * @description: call ocall_save_file to save m_hashs.bin file
 * @param data -> data
 * @param data_size -> the length of data
 */
void save_m_hashs_file(const char *g_path, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_m_hashs_file_path(g_path);
    ocall_save_file(file_path.c_str(), data, data_size);
}
