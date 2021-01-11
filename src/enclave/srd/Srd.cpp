#include "Srd.h"

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
    ocall_save_file(&crust_status, file_path.c_str(), data, data_size, STORE_TYPE_SRD);
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
    ocall_save_file(&crust_status, file_path.c_str(), data, data_size, STORE_TYPE_SRD);
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
    crust_status_t crust_status = CRUST_SUCCESS;
    if (srd_change_num != 0)
    {
        ocall_srd_change(&crust_status, srd_change_num);
        if (CRUST_SRD_NUMBER_EXCEED == crust_status)
        {
            sgx_thread_mutex_lock(&g_srd_task_mutex);
            g_srd_task = 0;
            sgx_thread_mutex_unlock(&g_srd_task_mutex);
        }
    }

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Set srd info failed! Error code:%lx\n", crust_status);
    }
}

/**
 * @description: seal one G srd files under directory, can be called from multiple threads
 */
void srd_increase()
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    Workload *wl = Workload::get_instance();

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
    char tmp_val[16];
    sgx_read_rand((unsigned char *)&tmp_val, 16);
    std::string tmp_dir = hexstring_safe(tmp_val, 16);

    // ----- Generate srd file ----- //
    // Create directory
    ocall_create_dir(&crust_status, tmp_dir.c_str(), STORE_TYPE_SRD);
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

        save_file(tmp_dir.c_str(), i, out_hash256, (unsigned char *)p_sealed_data, SRD_RAND_DATA_LENGTH);

        free(p_sealed_data);
        p_sealed_data = NULL;
    }

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);

    save_m_hashs_file(tmp_dir.c_str(), hashs, SRD_RAND_DATA_NUM * HASH_LENGTH);
    free(hashs);

    // Change G path name
    std::string new_g_path = hexstring_safe(&g_out_hash256, HASH_LENGTH);
    ocall_rename_dir(&crust_status, tmp_dir.c_str(), new_g_path.c_str(), STORE_TYPE_SRD);

    // Get g hash
    uint8_t *p_hash_u = (uint8_t *)enc_malloc(HASH_LENGTH);
    if (p_hash_u == NULL)
    {
        log_info("Seal random data failed! Malloc memory failed!\n");
        return;
    }
    memset(p_hash_u, 0, HASH_LENGTH);
    memcpy(p_hash_u, g_out_hash256, HASH_LENGTH);

    // ----- Update srd_hashs ----- //
    std::string hex_g_hash = hexstring_safe(p_hash_u, HASH_LENGTH);
    if (hex_g_hash.compare("") == 0)
    {
        log_err("Hexstring failed!\n");
        return;
    }
    // Add new g_hash to srd_hashs
    // Because add this p_hash_u to the srd_hashs, so we cannot free p_hash_u
    sgx_thread_mutex_lock(&wl->srd_mutex);
    wl->srd_hashs.push_back(p_hash_u);
    log_info("Seal random data -> %s, %luG success\n", hex_g_hash.c_str(), wl->srd_hashs.size());
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(1);
}

/**
 * @description: Decrease srd files under directory
 * @param change -> Total to be deleted space volumn
 * @param clear_metadata -> Clear metadata
 * @return: Decreased size
 */
size_t srd_decrease(size_t change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // ----- Choose to be deleted hash ----- //
    SafeLock sl(wl->srd_mutex);
    sl.lock();
    wl->deal_deleted_srd(false);
    // Get real change
    change = std::min(change, wl->srd_hashs.size());
    if (change <= 0)
    {
        return 0;
    }
    // Get change hashs
    std::vector<std::string> srd_del_hashs;
    std::vector<size_t> srd_del_indexes;
    for (size_t i = 1; i <= change; i++)
    {
        size_t index = wl->srd_hashs.size() - i;
        srd_del_hashs.push_back(hexstring_safe(wl->srd_hashs[index], HASH_LENGTH));
        srd_del_indexes.push_back(index);
    }
    std::reverse(srd_del_indexes.begin(), srd_del_indexes.end());
    long r_change = -(long)change;
    wl->set_srd_info(r_change);
    wl->delete_srd_meta(srd_del_indexes);
    sl.unlock();

    // Delete srd files
    for (auto hash : srd_del_hashs)
    {
        ocall_delete_folder_or_file(&crust_status, hash.c_str(), STORE_TYPE_SRD);
        if (CRUST_SUCCESS != crust_status)
        {
            log_warn("Delete path:%s failed! Error code:%lx\n", hash.c_str(), crust_status);
        }
    }

    return change;
}

/**
 * @description: Remove space outside main loop
 * @param change -> remove size
 */
void srd_remove_space(size_t change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // ----- Choose to be deleted hash ----- //
    SafeLock sl(wl->srd_mutex);
    sl.lock();
    // Get real change
    change = std::min(change, wl->srd_hashs.size());
    if (change <= 0)
    {
        return;
    }
    // Get change hashs
    std::vector<std::string> srd_del_hashs;
    for (size_t i = 1; i <= change; i++)
    {
        size_t index = wl->srd_hashs.size() - i;
        srd_del_hashs.push_back(hexstring_safe(wl->srd_hashs[index], HASH_LENGTH));
        wl->add_srd_to_deleted_buffer(index);
    }
    sl.unlock();

    // Delete srd files
    if (srd_del_hashs.size() > 0)
    {
        log_info("Will delete %ldG srd space for user data. This is normal.\n", srd_del_hashs.size());
        for (auto hash : srd_del_hashs)
        {
            ocall_delete_folder_or_file(&crust_status, hash.c_str(), STORE_TYPE_SRD);
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", hash.c_str(), crust_status);
            }
        }
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
        Workload *wl = Workload::get_instance();
        sgx_thread_mutex_lock(&wl->srd_mutex);
        long srd_num = (long)wl->srd_hashs.size();
        sgx_thread_mutex_unlock(&wl->srd_mutex);
        srd_num += get_srd_task();

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

/**
 * @description: Srd gets sealed data data
 * @param path -> Data path
 * @param p_data -> Pointer to pointer sealed srd data
 * @param data_size -> Poniter to sealed srd data size
 * @return: Get result
 */
crust_status_t srd_get_file(const char *path, uint8_t **p_data, size_t *data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    ocall_get_file(&crust_status, path, p_data, data_size, STORE_TYPE_SRD);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    uint8_t *p_sealed_data = (uint8_t *)enc_malloc(*data_size);
    if (p_sealed_data == NULL)
    {
        ocall_free_outer_buffer(&crust_status, p_data);
        return CRUST_MALLOC_FAILED;
    }
    memset(p_sealed_data, 0, *data_size);
    memcpy(p_sealed_data, *p_data, *data_size);

    ocall_free_outer_buffer(&crust_status, p_data);

    *p_data = p_sealed_data;

    return crust_status;
}
