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
crust_status_t save_file(const char *g_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_leaf_path(g_path, index, hash);
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_save_file(&crust_status, file_path.c_str(), data, data_size);
    return crust_status;
}

/**
 * @description: call ocall_save_file to save m_hashs.bin file
 * @param g_path -> g folder path
 * @param data -> data
 * @param data_size -> the length of data
 */
crust_status_t save_m_hashs_file(const char *g_path, const unsigned char *data, size_t data_size)
{
    std::string file_path = get_m_hashs_file_path(g_path);
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_save_file(&crust_status, file_path.c_str(), data, data_size);
    return crust_status;
}

/**
 * @description: seal one G empty files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void srd_increase_empty(const char *path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    unsigned char base_rand_data[SRD_RAND_DATA_LENGTH];
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    Workload *p_workload = Workload::get_instance();

    // Generate base random data
    sgx_read_rand(reinterpret_cast<unsigned char *>(&base_rand_data), sizeof(base_rand_data));

    // New and get now G hash index
    sgx_thread_mutex_lock(&g_workload_mutex);
    size_t now_index = p_workload->empty_g_hashs_number + 1;
    p_workload->empty_g_hashs_number++;
    sgx_thread_mutex_unlock(&g_workload_mutex);

    // Create directory
    std::string g_path = get_g_path(path, now_index);
    ocall_create_dir(&crust_status, g_path.c_str());

    // Generate all M hashs and store file to disk
    unsigned char *hashs = new unsigned char[SRD_RAND_DATA_NUM * HASH_LENGTH];
    for (size_t i = 0; i < SRD_RAND_DATA_NUM; i++)
    {
        seal_data_mrenclave(base_rand_data, SRD_RAND_DATA_LENGTH, &p_sealed_data, &sealed_data_size);

        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg((unsigned char *)p_sealed_data, SRD_RAND_DATA_LENGTH, &out_hash256);

        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            hashs[i * HASH_LENGTH + j] = out_hash256[j];
        }

        save_file(g_path.c_str(), i, out_hash256, (unsigned char *)p_sealed_data, SRD_RAND_DATA_LENGTH);

        free(p_sealed_data);
        p_sealed_data = NULL;
    }

    /* Generate G hashs */
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(g_path.c_str(), hashs, SRD_RAND_DATA_NUM * HASH_LENGTH);
    delete[] hashs;

    /* Change G path name */
    std::string new_g_path = get_g_path_with_hash(path, g_out_hash256);
    ocall_rename_dir(&crust_status, g_path.c_str(), new_g_path.c_str());

    sgx_thread_mutex_lock(&g_workload_mutex);
    uint8_t *p_hash = (uint8_t *)malloc(HASH_LENGTH);
    for (size_t i = 0; i < HASH_LENGTH; i++)
    {
        p_hash[i] = g_out_hash256[i];
    }
    p_workload->empty_g_hashs.push_back(p_hash);
    sgx_thread_mutex_unlock(&g_workload_mutex);

    log_info("Seal random data -> %s, %luG success\n", unsigned_char_array_to_hex_string(g_out_hash256, HASH_LENGTH).c_str(), now_index + 1);
}

/**
 * @description: decrease empty files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
size_t srd_decrease_empty(const char *path, size_t change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *p_workload = Workload::get_instance();
    sgx_thread_mutex_lock(&g_workload_mutex);
    size_t decrease_num = 0;

    for (auto it = p_workload->empty_g_hashs.begin(); (decrease_num < change) && it != this->empty_g_hashs.end(); it++)
    {
        ocall_delete_folder_or_file(&crust_status, get_g_path_with_hash(path, *it).c_str());
        decrease_num++;
    }

    sgx_thread_mutex_unlock(&g_workload_mutex);

    return decrease_num;
}
