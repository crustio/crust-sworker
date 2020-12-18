#include "Srd.h"

extern sgx_thread_mutex_t g_srd_mutex;
long g_srd_task = 0;
sgx_thread_mutex_t g_srd_task_mutex = SGX_THREAD_MUTEX_INITIALIZER;
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

    sgx_thread_mutex_lock(&g_srd_task_mutex);

    // Get real srd space
    long srd_change_num = 0;
    if (g_srd_task > SRD_MAX_PER_TURN)
    {
        srd_change_num = SRD_MAX_PER_TURN;
        g_srd_task -= SRD_MAX_PER_TURN;
    }
    else
    {
        srd_change_num = g_srd_task;
        g_srd_task = 0;
    }

    // Store remaining task
    std::string srd_task_str = std::to_string(g_srd_task);
    if (CRUST_SUCCESS != persist_set_unsafe(WL_SRD_REMAINING_TASK, reinterpret_cast<const uint8_t *>(srd_task_str.c_str()), srd_task_str.size()))
    {
        log_warn("Store srd remaining task failed!\n");
    }
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

    // Do srd
    if (srd_change_num != 0)
    {
        ocall_srd_change(srd_change_num);
    }

    // Update srd info
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string srd_info_str = wl->get_srd_info().dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Set srd info failed! Error code:%lx\n", crust_status);
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
 * @return: Decreased size
 */
size_t srd_decrease(long change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    uint32_t real_change = 0;
    uint32_t srd_total_num = 0;

    // Choose to be deleted g_hash index
    SafeLock sl(g_srd_mutex);
    sl.lock();
    wl->deal_deleted_srd(false);
    // Set delete set
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    change = std::min(change, (long)srd_total_num);
    if (change == 0)
    {
        return 0;
    }
    // Sort path by srd number
    std::unordered_map<std::string, std::vector<uint8_t *>> srd_del_path2hashs_um;
    std::vector<std::pair<std::string, uint32_t>> ordered_srd_path2hashs_v;
    for (auto path2hashs: wl->srd_path2hashs_m)
    {
        ordered_srd_path2hashs_v.push_back(std::make_pair(path2hashs.first, path2hashs.second.size()));
    }
    std::sort(ordered_srd_path2hashs_v.begin(), ordered_srd_path2hashs_v.end(), 
        [](std::pair<std::string, uint32_t> &v1, std::pair<std::string, uint32_t> &v2)
        {
            return v1.second < v2.second;
        }
    );
    // Do delete
    size_t disk_num = wl->srd_path2hashs_m.size();
    for (auto it = ordered_srd_path2hashs_v.begin(); 
            it != ordered_srd_path2hashs_v.end() && change > 0 && disk_num > 0; it++, disk_num--)
    {
        std::string path = it->first;
        size_t del_num = change / disk_num;
        if ((double)change / (double)disk_num - (double)del_num > 0)
        {
            del_num++;
        }
        if (wl->srd_path2hashs_m[path].size() <= del_num)
        {
            del_num = wl->srd_path2hashs_m[path].size();
        }
        auto sit = wl->srd_path2hashs_m[path].begin();
        auto eit = sit + del_num;
        srd_del_path2hashs_um[path].insert(srd_del_path2hashs_um[path].end(), sit, eit);
        // Delete related srd from meta
        wl->srd_path2hashs_m[path].erase(sit, eit);
        // Delete related path if there is no srd
        if (wl->srd_path2hashs_m[path].size() == 0)
        {
            wl->srd_path2hashs_m.erase(path);
        }
        change -= del_num;
        real_change += del_num;
        wl->set_srd_info(path, -del_num);
    }
    sl.unlock();

    // ----- Delete corresponding items ----- //
    // Do delete
    for (auto path2hashs : srd_del_path2hashs_um)
    {
        std::string del_dir = path2hashs.first;
        for (auto del_hash : path2hashs.second)
        {
            // --- Delete srd file --- //
            std::string del_path = path2hashs.first + "/" + hexstring_safe(del_hash, HASH_LENGTH);
            ocall_delete_folder_or_file(&crust_status, del_path.c_str());
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", del_path.c_str(), crust_status);
            }
        }
    }

    return real_change;
}

/**
 * @description: Update srd_path2hashs_m
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 */
void srd_update_metadata(const char *hashs, size_t hashs_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    json::JSON del_hashs_json = json::JSON::Load(std::string(hashs, hashs_len));
    std::unordered_map<std::string, std::vector<std::string>> del_dir2hashs_um;

    sgx_thread_mutex_lock(&g_srd_mutex);
    for (auto it = del_hashs_json.ObjectRange().begin(); it != del_hashs_json.ObjectRange().end(); it++)
    {
        std::string del_dir = it->first;
        size_t del_num = it->second.ToInt();
        std::vector<uint8_t*> *p_hashs = &wl->srd_path2hashs_m[del_dir];
        if (p_hashs->size() > 0)
        {
            if (p_hashs->size() < del_num)
            {
                del_num = p_hashs->size();
            }
            auto rit = p_hashs->rbegin();
            size_t reverse_index = p_hashs->size() - 1;
            std::vector<uint32_t> del_index_v;
            while (rit != p_hashs->rend() && del_num > 0)
            {
                del_dir2hashs_um[del_dir].push_back(hexstring_safe(*rit, HASH_LENGTH));
                del_index_v.push_back(reverse_index);
                rit++;
                del_num--;
                reverse_index--;
            }
            wl->add_srd_to_deleted_buffer(del_dir, del_index_v.begin(), del_index_v.end());
        }
    }
    sgx_thread_mutex_unlock(&g_srd_mutex);

    // Delete srd file
    for (auto dir2hashs : del_dir2hashs_um)
    {
        std::string del_dir = dir2hashs.first;
        log_debug("Disk path:%s will free %ldG srd space for user data. This is normal.\n", del_dir.c_str(), dir2hashs.second.size());
        for (auto g_hash : dir2hashs.second)
        {
            std::string del_path = del_dir + "/" + g_hash;
            ocall_delete_folder_or_file(&crust_status, del_path.c_str());
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", del_path.c_str(), crust_status);
            }
        }
    }

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());
    if (CRUST_SUCCESS != crust_status)
    {
        log_warn("Update srd info failed! Error code:%lx\n", crust_status);
    }
}

/**
 * @description: Get srd change
 * @return: Srd change 
 */
long get_srd_task()
{
    sgx_thread_mutex_lock(&g_srd_task_mutex);
    long srd_change = g_srd_task;
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

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

    sgx_thread_mutex_lock(&g_srd_task_mutex);
    g_srd_task += change;
    // Store remaining task
    std::string srd_task_str = std::to_string(g_srd_task);
    if (CRUST_SUCCESS != persist_set_unsafe(WL_SRD_REMAINING_TASK, reinterpret_cast<const uint8_t *>(srd_task_str.c_str()), srd_task_str.size()))
    {
        log_warn("Store srd remaining task failed!\n");
    }
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

    *real_change = change;

    return crust_status;
}
