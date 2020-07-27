#include "Srd.h"

extern sgx_thread_mutex_t g_srd_mutex;
std::unordered_set<std::string> g_srd_decreased_g_hashs_s;
long g_srd_change = 0;
sgx_thread_mutex_t g_srd_change_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint8_t *g_base_rand_buffer = NULL;
sgx_thread_mutex_t g_base_rand_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
 * @description: Do srd
 * */
void srd_change()
{
    // ----- Change and store srd task ----- //
    // Get real srd space
    sgx_thread_mutex_lock(&g_srd_change_mutex);
    long srd_change_num = 0;
    if (g_srd_change > SRD_MAX_PER_TURN)
    {
        srd_change_num = SRD_MAX_PER_TURN;
        g_srd_change -= SRD_MAX_PER_TURN;
    }
    else
    {
        srd_change_num = g_srd_change;
        g_srd_change = 0;
    }
    sgx_thread_mutex_unlock(&g_srd_change_mutex);

    // Do srd
    if (srd_change_num != 0)
    {
        ocall_srd_change(srd_change_num);
    }
}

/**
 * @description: seal one G srd files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void srd_increase(const char *path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    Workload *wl = Workload::get_instance();
    std::string path_str(path);

    // Generate base random data
    do
    {
        if (g_base_rand_buffer == NULL)
        {
            sgx_thread_mutex_lock(&g_base_rand_buffer_mutex);
            if (g_base_rand_buffer != NULL)
            {
                sgx_thread_mutex_unlock(&g_base_rand_buffer_mutex);
                break;
            }
            g_base_rand_buffer = (uint8_t *)enc_malloc(SRD_RAND_DATA_LENGTH);
            memset(g_base_rand_buffer, 0, SRD_RAND_DATA_LENGTH);
            sgx_read_rand(g_base_rand_buffer, sizeof(g_base_rand_buffer));
            sgx_thread_mutex_unlock(&g_base_rand_buffer_mutex);
        }
    } while (0);

    // New and get now G hash index
    size_t now_index = 0;
    sgx_read_rand((unsigned char *)&now_index, 8);

    // ----- Generate srd file ----- //
    // Create directory
    std::string g_path = get_g_path(path, now_index);
    ocall_create_dir(&crust_status, g_path.c_str());

    // Generate all M hashs and store file to disk
    unsigned char *hashs = new unsigned char[SRD_RAND_DATA_NUM * HASH_LENGTH];
    for (size_t i = 0; i < SRD_RAND_DATA_NUM; i++)
    {
        seal_data_mrenclave(g_base_rand_buffer, SRD_RAND_DATA_LENGTH, &p_sealed_data, &sealed_data_size);

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

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(g_path.c_str(), hashs, SRD_RAND_DATA_NUM * HASH_LENGTH);
    delete[] hashs;

    // Change G path name
    std::string new_g_path = get_g_path_with_hash(path, g_out_hash256);
    ocall_rename_dir(&crust_status, g_path.c_str(), new_g_path.c_str());

    // Get g hash
    uint8_t *p_hash = (uint8_t *)enc_malloc(HASH_LENGTH);
    memset(p_hash, 0, HASH_LENGTH);
    memcpy(p_hash, g_out_hash256, HASH_LENGTH);

    // ----- Update related items ----- //
    std::string hex_g_hash = hexstring_safe(p_hash, HASH_LENGTH);

    // Add new g_hash to srd_path2hashs_m
    // Cause add this p_hash to the srd_path2hashs_m we cannot free p_hash
    sgx_thread_mutex_lock(&g_srd_mutex);
    wl->srd_path2hashs_m[path_str].push_back(p_hash);
    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    log_info("Seal random data -> %s, %luG success\n", hex_g_hash.c_str(), srd_total_num);
    sgx_thread_mutex_unlock(&g_srd_mutex);

    // ----- Update srd info ----- //
    ocall_srd_info_lock();
    size_t srd_info_len = 0;
    uint8_t *p_srd_info = NULL;
    json::JSON srd_info_json;
    if (CRUST_SUCCESS == persist_get_unsafe("srd_info", &p_srd_info, &srd_info_len))
    {
        srd_info_json = json::JSON::Load(std::string(reinterpret_cast<char*>(p_srd_info), srd_info_len));
    }
    srd_info_json[path_str]["assigned"] = srd_info_json[path_str]["assigned"].ToInt() + 1;
    std::string srd_info_str = srd_info_json.dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe("srd_info", reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Set srd info failed! Error code:%lx\n", crust_status);
    }
    ocall_srd_info_unlock();
}

/**
 * @description: Decrease srd files under directory
 * @param change -> Total to be deleted space volumn
 * @param del_indexes -> To be deleted srd index in srd_path2hashs_m
 * @return: Decreased size
 */
size_t srd_decrease(long change, std::map<std::string, std::set<size_t>> *srd_del_index_m)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    uint32_t change_num = 0;
    uint32_t srd_total_num = 0;
    uint32_t srd_del_num = 0;

    // Set delete set
    std::map<std::string, std::set<size_t>> tmp_m;
    if (srd_del_index_m == NULL)
    {
        srd_del_index_m = &tmp_m;
    }
    for (auto it : (*srd_del_index_m))
    {
        srd_del_num += it.second.size();
    }
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    change = std::min(change, (long)srd_total_num);
    if (change == 0)
    {
        return 0;
    }

    // Randomly choose to be deleted g_hash index
    uint32_t rand_val;
    size_t rand_idx;
    std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry;
    while (srd_del_num < change)
    {
        do
        {
            sgx_read_rand((uint8_t*)&rand_val, 4);
            chose_entry = wl->srd_path2hashs_m.begin();
            for (int i = rand_val % wl->srd_path2hashs_m.size(); i > 0; i--)
            {
                chose_entry++;
            }
            rand_idx = rand_val % chose_entry->second.size();
        } while ((*srd_del_index_m)[chose_entry->first].find(rand_idx) != (*srd_del_index_m)[chose_entry->first].end());
        (*srd_del_index_m)[chose_entry->first].insert(rand_idx);
        srd_del_num++;
    }

    // Delete chose hashs in srd_path2hashs_m
    std::map<std::string, std::vector<std::string>> del_path2hashs_m;
    for (auto it : (*srd_del_index_m))
    {
        for (auto rit = it.second.rbegin(); rit != it.second.rend(); rit++)
        {
            std::vector<uint8_t*> *p_entry = &wl->srd_path2hashs_m[it.first];
            if ((*p_entry)[*rit] != NULL)
            {
                del_path2hashs_m[it.first].push_back(hexstring_safe((*p_entry)[*rit], HASH_LENGTH));
                free((*p_entry)[*rit]);
            }
            p_entry->erase(p_entry->begin() + *rit);
        }
    }

    // ----- Delete corresponding items ----- //
    // Get srd info
    uint8_t *p_srd_info = NULL;
    size_t srd_info_len = 0;
    if (CRUST_SUCCESS != persist_get_unsafe("srd_info", &p_srd_info, &srd_info_len))
    {
        log_err("Get srd info failed!\n");
    }
    json::JSON srd_info_json = json::JSON::Load(std::string(reinterpret_cast<char*>(p_srd_info), srd_info_len));
    // Do delete
    for (auto path_2_hash : del_path2hashs_m)
    {
        json::JSON hashs_json;
        std::string del_dir = path_2_hash.first;
        for (auto del_hash : path_2_hash.second)
        {
            // --- Delete srd file --- //
            std::string del_path = path_2_hash.first + "/" + del_hash;
            ocall_delete_folder_or_file(&crust_status, del_path.c_str());
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", del_path.c_str(), crust_status);
            }
            else
            {
                change_num++;
            }
            // --- Delete hash to path --- //
            persist_del(del_hash);
            // Add hash pointer to hashs_v
            hashs_json.append(del_hash);
        }
        // --- Reduce assigned space in srd info --- //
        srd_info_json[del_dir]["assigned"] = srd_info_json[del_dir]["assigned"].ToInt() - path_2_hash.second.size();
    }
    // Update srd info
    std::string srd_info_str = srd_info_json.dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe("srd_info", 
                    reinterpret_cast<const uint8_t*>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_err("Delete punish g: set srd info failed! Error code:%lx\n", crust_status);
    }

    // Update workload in metadata
    if (CRUST_SUCCESS != (crust_status = id_metadata_set_or_append(ID_WORKLOAD, wl->serialize_srd(false))))
    {
        log_err("Store metadata failed! Error code:%lx\n", crust_status);
    }

    return change_num;
}

/**
 * @description: Update srd_path2hashs_m
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 * */
void srd_update_metadata(const char *hashs, size_t hashs_len)
{
    sgx_thread_mutex_lock(&g_srd_mutex);
    ocall_srd_info_lock();

    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    json::JSON del_hashs_json = json::JSON::Load(std::string(hashs, hashs_len));

    // Get srd info
    uint8_t *p_srd_info = NULL;
    size_t srd_info_len = 0;
    if (CRUST_SUCCESS != (crust_status = persist_get_unsafe("srd_info", &p_srd_info, &srd_info_len)))
    {
        log_warn("Get srd info failed! Error code:%lx\n", crust_status);
    }
    json::JSON srd_info_json = json::JSON::Load(std::string(reinterpret_cast<char*>(p_srd_info), srd_info_len));
    if (p_srd_info != NULL)
    {
        free(p_srd_info);
    }

    for (auto it = del_hashs_json.ObjectRange().begin(); it != del_hashs_json.ObjectRange().end(); it++)
    {
        // Check sched flag
        sched_check(SCHED_SRD_CHECK_RESERVED, g_srd_mutex);

        std::vector<uint8_t*> *p_entry = &wl->srd_path2hashs_m[it->first];
        for (int i = it->second.ToInt(); i > 0; i--)
        {
            std::string hex_g_hash = hexstring_safe(p_entry->back(), HASH_LENGTH);
            if (p_entry->back() != NULL)
            {
                free(p_entry->back());
            }
            p_entry->pop_back();
            // Delete srd file
            std::string del_path = std::string(it->first).append("/").append(hex_g_hash);
            ocall_delete_folder_or_file(&crust_status, del_path.c_str());
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", del_path.c_str(), crust_status);
            }
            else
            {
                srd_info_json[it->first]["assigned"] = srd_info_json[it->first]["assigned"].ToInt() - 1;
            }
            // Delete hash to path mapping
            persist_del(hex_g_hash);
        }
    }

    // Update srd info
    std::string srd_info_str = srd_info_json.dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe("srd_info", reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Update srd info failed! Error code:%lx\n", crust_status);
    }

    ocall_srd_info_unlock();
    sgx_thread_mutex_unlock(&g_srd_mutex);
}

/**
 * @description: Get srd change
 * @return: Srd change 
 * */
long get_srd_change()
{
    sgx_thread_mutex_lock(&g_srd_change_mutex);
    long srd_change = g_srd_change;
    sgx_thread_mutex_unlock(&g_srd_change_mutex);

    return srd_change;
}

/**
 * @description: Set srd change
 * @param change -> Srd change
 * */
void set_srd_change(long change)
{
    sgx_thread_mutex_lock(&g_srd_change_mutex);
    g_srd_change = change;
    sgx_thread_mutex_unlock(&g_srd_change_mutex);
}
