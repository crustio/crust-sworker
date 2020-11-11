#include "Srd.h"

extern sgx_thread_mutex_t g_srd_mutex;
long g_srd_change = 0;
sgx_thread_mutex_t g_srd_change_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint8_t *g_base_rand_buffer = NULL;
sgx_thread_mutex_t g_base_rand_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

// TODO: store in DB with bytes
/**
 * @description: call ocall_save_file to save file
 * @param g_path -> g folder path
 * @param index -> m file's index
 * @param hash -> m file's hash
 * @param data -> m file's data
 * @param data_size -> the length of m file's data
 * @return: Save status
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
 * @return: Save status
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
 */
void srd_change()
{
    Workload *wl = Workload::get_instance();
    if (ENC_UPGRADE_STATUS_SUCCESS == wl->get_upgrade_status())
    {
        return;
    }

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

    // Update srd info
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_srd_info_lock();
    std::string srd_info_str = wl->get_srd_info().dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Set srd info failed! Error code:%lx\n", crust_status);
    }
    ocall_srd_info_unlock();
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
            SafeLock sl(g_base_rand_buffer_mutex);
            sl.lock();
            if (g_base_rand_buffer != NULL)
            {
                break;
            }
            g_base_rand_buffer = (uint8_t *)enc_malloc(SRD_RAND_DATA_LENGTH);
            if (g_base_rand_buffer == NULL)
            {
                log_err("Malloc memory failed!\n");
                return;
            }
            memset(g_base_rand_buffer, 0, SRD_RAND_DATA_LENGTH);
            sgx_read_rand(g_base_rand_buffer, sizeof(g_base_rand_buffer));
        }
    } while (0);

    // Generate current G hash index
    size_t now_index = 0;
    sgx_read_rand((unsigned char *)&now_index, 8);

    // ----- Generate srd file ----- //
    // Create directory
    std::string g_path = get_g_path(path, now_index);
    ocall_create_dir(&crust_status, g_path.c_str());
    if (CRUST_SUCCESS != crust_status)
    {
        return;
    }

    // Generate all M hashs and store file to disk
    uint8_t *hashs = (uint8_t *)enc_malloc(SRD_RAND_DATA_NUM * HASH_LENGTH);
    if (hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return;
    }
    for (size_t i = 0; i < SRD_RAND_DATA_NUM; i++)
    {
        crust_status = seal_data_mrenclave(g_base_rand_buffer, SRD_RAND_DATA_LENGTH, &p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            return;
        }

        sgx_sha256_hash_t out_hash256;
        sgx_sha256_msg((uint8_t *)p_sealed_data, SRD_RAND_DATA_LENGTH, &out_hash256);

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
    free(hashs);

    // Change G path name
    std::string new_g_path = get_g_path_with_hash(path, g_out_hash256);
    ocall_rename_dir(&crust_status, g_path.c_str(), new_g_path.c_str());

    // Get g hash
    uint8_t *p_hash_u = (uint8_t *)enc_malloc(HASH_LENGTH);
    if (p_hash_u == NULL)
    {
        log_info("Seal random data failed! Malloc memory failed!\n");
        return;
    }
    memset(p_hash_u, 0, HASH_LENGTH);
    memcpy(p_hash_u, g_out_hash256, HASH_LENGTH);

    // ----- Update srd_path2hashs_m ----- //
    std::string hex_g_hash = hexstring_safe(p_hash_u, HASH_LENGTH);
    if (hex_g_hash.compare("") == 0)
    {
        log_err("Hexstring failed!\n");
        return;
    }
    // Add new g_hash to srd_path2hashs_m
    // Because add this p_hash_u to the srd_path2hashs_m, so we cannot free p_hash_u
    sgx_thread_mutex_lock(&g_srd_mutex);
    wl->srd_path2hashs_m[path_str].push_back(p_hash_u);
    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    log_info("Seal random data -> %s, %luG success\n", hex_g_hash.c_str(), srd_total_num);
    sgx_thread_mutex_unlock(&g_srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(path_str, 1);
}

/**
 * @description: Decrease srd files under directory
 * @param change -> Total to be deleted space volumn
 * @param srd_del_index_m -> To be deleted srd path to index in srd_path2hashs_m
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

    // Choose to be deleted g_hash index
    std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry;
    size_t sAcc = 1;
    bool end_of_traverse = false;
    while (srd_del_num < change && !end_of_traverse)
    {
        end_of_traverse = true;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++)
        {
            if (it->second.size() >= sAcc)
            {
                size_t tIdx = it->second.size() - sAcc;
                if ((*srd_del_index_m)[it->first].find(tIdx) == (*srd_del_index_m)[it->first].end())
                {
                    (*srd_del_index_m)[it->first].insert(tIdx);
                    srd_del_num++;
                }
                end_of_traverse = false;
            }
        }
        sAcc++;
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
    // Do delete
    for (auto path_2_hash : del_path2hashs_m)
    {
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
        }
        // Reduce assigned space in srd info
        wl->set_srd_info(del_dir, -(long)(path_2_hash.second.size()));
    }

    return change_num;
}

/**
 * @description: Update srd_path2hashs_m
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 */
void srd_update_metadata(const char *hashs, size_t hashs_len)
{
    sgx_thread_mutex_lock(&g_srd_mutex);
    ocall_srd_info_lock();

    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    json::JSON del_hashs_json = json::JSON::Load(std::string(hashs, hashs_len));

    for (auto it = del_hashs_json.ObjectRange().begin(); it != del_hashs_json.ObjectRange().end(); it++)
    {
        // Check sched flag
        sched_check(SCHED_SRD_CHECK_RESERVED, g_srd_mutex);

        std::vector<uint8_t*> *p_entry = &wl->srd_path2hashs_m[it->first];
        size_t real_deleted_num = std::min((size_t)it->second.ToInt(), p_entry->size());
        for (size_t i = real_deleted_num; i > 0; i--)
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
                wl->set_srd_info(it->first, -1);
            }
        }
    }

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Update srd info failed! Error code:%lx\n", crust_status);
    }

    ocall_srd_info_unlock();
    sgx_thread_mutex_unlock(&g_srd_mutex);
}

/**
 * @description: Get srd change
 * @return: Srd change 
 */
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
 */
crust_status_t change_srd_task(long change, long *real_change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    // Check if srd number exceeds upper limit
    if (change > 0)
    {
        sgx_thread_mutex_lock(&g_srd_mutex);
        size_t srd_num = 0;
        for (auto srds : Workload::get_instance()->srd_path2hashs_m)
        {
            srd_num += srds.second.size();
        }
        sgx_thread_mutex_unlock(&g_srd_mutex);
        if (srd_num >= SRD_NUMBER_UPPER_LIMIT)
        {
            log_warn("No srd will be added!Srd size has reached the upper limit:%ldG!\n", SRD_NUMBER_UPPER_LIMIT);
            change = 0;
            crust_status = CRUST_SRD_NUMBER_EXCEED;
        }
        else if (srd_num + change > SRD_NUMBER_UPPER_LIMIT)
        {
            log_warn("To be added srd number:%ldG(srd upper limit:%ldG)\n", change, SRD_NUMBER_UPPER_LIMIT);
            change = SRD_NUMBER_UPPER_LIMIT - srd_num;
            crust_status = CRUST_SRD_NUMBER_EXCEED;
        }
    }

    sgx_thread_mutex_lock(&g_srd_change_mutex);
    g_srd_change += change;
    sgx_thread_mutex_unlock(&g_srd_change_mutex);

    *real_change = change;

    return crust_status;
}
