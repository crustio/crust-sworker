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
    std::string path_str(path);

    // Get g_hashs under path
    uint8_t *p_g_hashs = NULL;
    size_t g_hashs_len = 0;
    persist_get(path_str, &p_g_hashs, &g_hashs_len);
    json::JSON path_2_g_hashs_j;
    path_2_g_hashs_j = json::JSON::Load(std::string(reinterpret_cast<char*>(p_g_hashs), g_hashs_len));

    // Generate base random data
    sgx_read_rand(reinterpret_cast<unsigned char *>(&base_rand_data), sizeof(base_rand_data));

    // New and get now G hash index
    size_t now_index = 0;
    sgx_read_rand((unsigned char *)&now_index, 8);

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
    // Persist g_hash's corresponding path
    char *p_hex_hash = hexstring_safe(p_hash, HASH_LENGTH);
    std::string hex_hash_str(p_hex_hash, HASH_LENGTH * 2);
    path_2_g_hashs_j[path_str].append(std::string(reinterpret_cast<char*>(p_hash), HASH_LENGTH));
    std::string path_2_g_hashs_str = path_2_g_hashs_j.dump();
    if (CRUST_SUCCESS != persist_set(path_str, reinterpret_cast<const uint8_t *>(path_2_g_hashs_str.c_str()), path_2_g_hashs_str.size()))
    {
        log_err("Store path:%s to g hashs:%s map failed!\n", path, p_hex_hash);
    }
    if (CRUST_SUCCESS != persist_add(hex_hash_str, reinterpret_cast<const uint8_t *>(path), strlen(path)))
    {
        log_err("Store g_hash:%s failed!\n", p_hex_hash);
    }
    if (p_hex_hash != NULL)
    {
        free(p_hex_hash);
    }
    log_info("Seal random data -> %s, %luG success\n", unsigned_char_array_to_hex_string(g_out_hash256, HASH_LENGTH).c_str(), p_workload->empty_g_hashs.size());
    sgx_thread_mutex_unlock(&g_workload_mutex);
}

/**
 * @description: decrease empty files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
size_t srd_decrease_empty(const char *path, size_t change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    size_t change_num = 0;
    uint8_t *p_g_hashs = NULL;
    size_t g_hashs_len = 0;
    if (CRUST_SUCCESS != persist_get(std::string(path), &p_g_hashs, &g_hashs_len))
    {
        log_err("Get path:%s to g hashs map failed!\n", path);
        return change_num;
    }
    json::JSON path_2_g_hashs_j = json::JSON::Load(std::string(reinterpret_cast<char*>(p_g_hashs), g_hashs_len));
    change = std::min(change, (size_t)path_2_g_hashs_j.size());
    change_num = change;
    auto p_range = path_2_g_hashs_j.ArrayRange();
    for (auto it = p_range.begin(); it != p_range.end() && change > 0; it++, change--)
    {
        p_range.object->erase(it);
        ocall_delete_folder_or_file(&crust_status, get_g_path_with_hash(path, reinterpret_cast<const uint8_t *>(it->ToString().c_str())).c_str());
    }

    return change_num;
}
