#include "Srd.h"

extern sgx_thread_mutex_t g_workload_mutex;

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
 * @param g_path -> g folder path
 * @param data -> data
 * @param data_size -> the length of data
 */
void save_m_hashs_file(const char *g_path, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_m_hashs_file_path(g_path);
    ocall_save_file(file_path.c_str(), data, data_size);
}

/**
 * @description: seal one G empty files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void increase_empty(const char *path)
{
    unsigned char base_rand_data[PLOT_RAND_DATA_LENGTH];
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;

    // Generate base random data
    sgx_read_rand(reinterpret_cast<unsigned char *>(&base_rand_data), sizeof(base_rand_data));

    // New and get now G hash index
    sgx_thread_mutex_lock(&g_workload_mutex);
    size_t now_index = get_workload()->empty_g_hashs.size();
    uint8_t *p_hash = (uint8_t *)malloc(HASH_LENGTH);
    if (p_hash == NULL)
    {
        sgx_thread_mutex_unlock(&g_workload_mutex);
        return;
    }
    get_workload()->empty_g_hashs.push_back(p_hash);
    for (size_t i = 0; i < HASH_LENGTH; i++)
    {
        get_workload()->empty_g_hashs[now_index][i] = 0;
    }
    sgx_thread_mutex_unlock(&g_workload_mutex);

    // Create directory
    std::string g_path = get_g_path(path, now_index);
    ocall_create_dir(g_path.c_str());

    // Generate all M hashs and store file to disk
    unsigned char *hashs = new unsigned char[PLOT_RAND_DATA_NUM * HASH_LENGTH];
    for (size_t i = 0; i < PLOT_RAND_DATA_NUM; i++)
    {
        seal_data_mrenclave(base_rand_data, PLOT_RAND_DATA_LENGTH, &p_sealed_data, &sealed_data_size);

        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg((unsigned char *)p_sealed_data, PLOT_RAND_DATA_LENGTH, &out_hash256);

        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            hashs[i * HASH_LENGTH + j] = out_hash256[j];
        }

        save_file(g_path.c_str(), i, out_hash256, (unsigned char *)p_sealed_data, PLOT_RAND_DATA_LENGTH);

        free(p_sealed_data);
        p_sealed_data = NULL;
    }

    /* Generate G hashs */
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, PLOT_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(g_path.c_str(), hashs, PLOT_RAND_DATA_NUM * HASH_LENGTH);
    delete[] hashs;

    /* Change G path name */
    std::string new_g_path = get_g_path_with_hash(path, g_out_hash256);
    ocall_rename_dir(g_path.c_str(), new_g_path.c_str());

    sgx_thread_mutex_lock(&g_workload_mutex);
    for (size_t i = 0; i < HASH_LENGTH; i++)
    {
        get_workload()->empty_g_hashs[now_index][i] = g_out_hash256[i];
    }
    sgx_thread_mutex_unlock(&g_workload_mutex);

    log_info("Plot file -> %s, %luG success\n", unsigned_char_array_to_hex_string(g_out_hash256, HASH_LENGTH).c_str(), now_index + 1);
}

/**
 * @description: decrease empty files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
size_t decrease_empty(const char *path, size_t change)
{
    Workload *workload = get_workload();
    sgx_thread_mutex_lock(&g_workload_mutex);
    size_t decrease_num = 0;

    for (size_t i = workload->empty_g_hashs.size(); (decrease_num < change) && (i > 0); i--)
    {
        if (!is_null_hash(workload->empty_g_hashs[i - 1]))
        {
            ocall_delete_folder_or_file(get_g_path_with_hash(path, workload->empty_g_hashs[i - 1]).c_str());
            decrease_num++;
        }
    }

    sgx_thread_mutex_unlock(&g_workload_mutex);

    return decrease_num;
}

/**
 * @description: generate empty root hash by using workload->empty_g_hashs 
 */
void generate_empty_root(void)
{
    sgx_thread_mutex_lock(&g_workload_mutex);

    // Get hashs for hash
    unsigned char *hashs = (unsigned char *)malloc(get_workload()->empty_g_hashs.size() * HASH_LENGTH);
    size_t hashs_length = 0;

    for (size_t i = 0; i < get_workload()->empty_g_hashs.size(); i++)
    {
        if (!is_null_hash(get_workload()->empty_g_hashs[i]))
        {
            for (size_t j = 0; j < HASH_LENGTH; j++)
            {
                hashs[i * 32 + j] = get_workload()->empty_g_hashs[i][j];
            }
            hashs_length += HASH_LENGTH;
        }
    }

    if (hashs_length == 0)
    {
        get_workload()->empty_disk_capacity = 0;
        for (size_t i = 0; i < HASH_LENGTH; i++)
        {
            get_workload()->empty_root_hash[i] = 0;
        }
    }
    else
    {
        get_workload()->empty_disk_capacity = hashs_length / HASH_LENGTH;
        sgx_sha256_msg(hashs, (uint32_t)hashs_length, &get_workload()->empty_root_hash);
    }

    free(hashs);
    sgx_thread_mutex_unlock(&g_workload_mutex);
}
