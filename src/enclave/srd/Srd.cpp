#include "Srd.h"

long g_srd_task = 0;
sgx_thread_mutex_t g_srd_task_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint8_t *g_base_rand_buffer = NULL;
sgx_thread_mutex_t g_base_rand_buffer_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
    if (ENC_UPGRADE_STATUS_NONE != wl->get_upgrade_status())
    {
        return;
    }

    // Check if validation has been applied or not
    if (!wl->report_has_validated_proof())
    {
        return;
    }

    SafeLock sl_task(g_srd_task_mutex);
    sl_task.lock();
    if (0 == g_srd_task)
        return;

    // Get real srd space
    long srd_change_num = 0;
    if (g_srd_task > SRD_MAX_INC_PER_TURN)
    {
        srd_change_num = SRD_MAX_INC_PER_TURN;
        g_srd_task -= SRD_MAX_INC_PER_TURN;
    }
    else if (g_srd_task > 0)
    {
        srd_change_num = g_srd_task;
        g_srd_task = 0;
    }
    else if (g_srd_task < 0)
    {
        srd_change_num = std::max(g_srd_task, (long)-SRD_MAX_DEC_PER_TURN);
        g_srd_task -= srd_change_num;
    }
    sl_task.unlock();

    // Do srd
    crust_status_t crust_status = CRUST_SUCCESS;
    if (srd_change_num != 0)
    {
        ocall_srd_change(&crust_status, srd_change_num);
        if (CRUST_SRD_NUMBER_EXCEED == crust_status)
        {
            sl_task.lock();
            g_srd_task = 0;
            sl_task.unlock();
        }
    }

    // Store remaining task
    sl_task.lock();
    std::string srd_task_str = std::to_string(g_srd_task);
    if (CRUST_SUCCESS != persist_set_unsafe(WL_SRD_REMAINING_TASK, reinterpret_cast<const uint8_t *>(srd_task_str.c_str()), srd_task_str.size()))
    {
        log_warn("Store srd remaining task failed!\n");
    }
    // Set srd remaining task
    wl->set_srd_remaining_task(g_srd_task);
    std::string srd_info_str = wl->get_srd_info().dump();
    ocall_set_srd_info(reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());
    sl_task.unlock();
}

/**
 * @description: seal one G srd files under directory, can be called from multiple threads
 * @param uuid -> Disk path uuid
 * @return: Srd increase result
 */
crust_status_t srd_increase(const char *uuid)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Get uuid bytes
    uint8_t *p_uuid_u = hex_string_to_bytes(uuid, UUID_LENGTH * 2);
    if (p_uuid_u == NULL)
    {
        log_err("Get uuid bytes failed! Invalid uuid:%s\n", uuid);
        return CRUST_UNEXPECTED_ERROR;
    }
    Defer def_uuid([&p_uuid_u](void) { free(p_uuid_u); });

    // Check if validation has been applied or not
    if (!wl->report_has_validated_proof())
    {
        return CRUST_VALIDATE_HIGH_PRIORITY;
    }

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
                return CRUST_MALLOC_FAILED;
            }
            memset(g_base_rand_buffer, 0, SRD_RAND_DATA_LENGTH);
            sgx_read_rand(g_base_rand_buffer, sizeof(g_base_rand_buffer));
        }
    } while (0);

    // Generate current G hash index
    size_t tmp_val_len = 18;
    char tmp_val[tmp_val_len];
    sgx_read_rand((unsigned char *)&tmp_val, tmp_val_len);
    std::string tmp_val_str = hexstring_safe(tmp_val, tmp_val_len);
    char *p_mid_dir = tmp_val;
    std::string mid_dir = tmp_val_str.substr(0, LAYER_LENGTH * 2);
    std::string tmp_dir = uuid + tmp_val_str;

    // ----- Generate srd file ----- //
    // Create directory
    ocall_create_dir(&crust_status, tmp_dir.c_str(), STORE_TYPE_SRD);
    if (CRUST_SUCCESS != crust_status)
    {
        log_err("Create tmp directory failed! Error code:%lx\n", crust_status);
        return crust_status;
    }
    // Delete tmp directory if failed
    Defer def_del_dir([&crust_status, &tmp_dir](void) {
        if (CRUST_SUCCESS != crust_status)
        {
            crust_status_t del_ret = CRUST_SUCCESS;
            ocall_delete_folder_or_file(&del_ret, tmp_dir.c_str(), STORE_TYPE_SRD);
            if (CRUST_SUCCESS != del_ret)
            {
                log_warn("Delete temp directory %s failed! Error code:%lx\n", tmp_dir.c_str(), del_ret);
            }
        }
    });

    // Generate all M hashs and store file to disk
    uint8_t *m_hashs = (uint8_t *)enc_malloc(SRD_RAND_DATA_NUM * HASH_LENGTH);
    if (m_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return crust_status = CRUST_MALLOC_FAILED;
    }
    Defer defer_hashs([&m_hashs](void) { free(m_hashs); });
    for (size_t i = 0; i < SRD_RAND_DATA_NUM; i++)
    {
        sgx_sealed_data_t *p_sealed_data = NULL;
        size_t sealed_data_size = 0;
        crust_status = seal_data_mrenclave(g_base_rand_buffer, SRD_RAND_DATA_LENGTH, &p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            log_err("Seal random data failed! Error code:%lx\n", crust_status);
            return crust_status;
        }
        Defer defer_sealed_data([&p_sealed_data](void) { free(p_sealed_data); });

        sgx_sha256_hash_t m_hash;
        sgx_sha256_msg((uint8_t *)p_sealed_data, SRD_RAND_DATA_LENGTH, &m_hash);
        memcpy(m_hashs + i * HASH_LENGTH, m_hash, HASH_LENGTH);

        std::string m_data_path = get_leaf_path(tmp_dir.c_str(), i, m_hash);
        ocall_save_file(&crust_status, m_data_path.c_str(), reinterpret_cast<const uint8_t *>(p_sealed_data), SRD_RAND_DATA_LENGTH, STORE_TYPE_SRD);
        if (CRUST_SUCCESS != crust_status)
        {
            log_err("Save srd file(%s) failed! Error code:%lx\n", tmp_dir.c_str(), crust_status);
            return crust_status;
        }
    }

    // Generate G hashs
    sgx_sha256_hash_t g_hash;
    sgx_sha256_msg(m_hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_hash);

    crust_status = save_m_hashs_file(tmp_dir.c_str(), m_hashs, SRD_RAND_DATA_NUM * HASH_LENGTH);
    if (CRUST_SUCCESS != crust_status)
    {
        log_err("Save srd(%s) metadata failed!\n", tmp_dir.c_str());
        return crust_status;
    }

    // Change G path name
    std::string g_hash_hex = hexstring_safe(&g_hash, HASH_LENGTH);
    std::string g_hash_path = uuid + mid_dir + g_hash_hex;
    ocall_rename_dir(&crust_status, tmp_dir.c_str(), g_hash_path.c_str(), STORE_TYPE_SRD);
    if (CRUST_SUCCESS != crust_status)
    {
        log_err("Rename directory %s to %s failed!\n", tmp_dir.c_str(), g_hash_path.c_str());
        return crust_status;
    }
    // ----- Update srd_hashs ----- //
    // Add new g_hash to srd_hashs
    // Because add this p_hash_u to the srd_hashs, so we cannot free p_hash_u
    uint8_t *srd_item = (uint8_t *)enc_malloc(SRD_LENGTH);
    if (srd_item == NULL)
    {
        log_err("Malloc for srd item failed!\n");
        return crust_status = CRUST_MALLOC_FAILED;
    }
    memset(srd_item, 0, SRD_LENGTH);
    memcpy(srd_item, p_uuid_u, UUID_LENGTH);
    memcpy(srd_item + UUID_LENGTH, p_mid_dir, LAYER_LENGTH);
    memcpy(srd_item + UUID_LENGTH + LAYER_LENGTH, g_hash, HASH_LENGTH);
    sgx_thread_mutex_lock(&wl->srd_mutex);
    wl->srd_hashs.push_back(srd_item);
    log_info("Seal random data -> %s, %luG success\n", g_hash_hex.c_str(), wl->srd_hashs.size());
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(uuid, 1);

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    ocall_set_srd_info(reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());

    return CRUST_SUCCESS;
}

/**
 * @description: Decrease srd files under directory
 * @param change -> Total to be deleted space volumn
 * @return: Decreased size
 */
size_t srd_decrease(size_t change)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // ----- Choose to be deleted hash ----- //
    SafeLock sl(wl->srd_mutex);
    sl.lock();
    wl->deal_deleted_srd_nolock();
    // Get real change
    change = std::min(change, wl->srd_hashs.size());
    if (change <= 0)
    {
        return 0;
    }
    // Get change hashs
    // Note: Cannot push srd hash pointer to vector because it will be deleted later
    std::vector<std::string> del_srds;
    std::vector<size_t> del_indexes;
    for (size_t i = 1; i <= change; i++)
    {
        size_t index = wl->srd_hashs.size() - i;
        del_srds.push_back(hexstring_safe(wl->srd_hashs[index], SRD_LENGTH));
        del_indexes.push_back(index);
    }
    std::reverse(del_indexes.begin(), del_indexes.end());
    wl->delete_srd_meta(del_indexes);
    sl.unlock();

    // Delete srd files
    for (auto srd : del_srds)
    {
        // Delete srd data
        ocall_delete_folder_or_file(&crust_status, srd.c_str(), STORE_TYPE_SRD);
        if (CRUST_SUCCESS != crust_status)
        {
            log_warn("Delete path:%s failed! Error code:%lx\n", srd.c_str(), crust_status);
        }
    }

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    ocall_set_srd_info(reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());

    return change;
}

/**
 * @description: Remove space outside main loop
 * @param data -> Pointer to deleted srd info
 * @param data_size -> Data size
 */
void srd_remove_space(const char *data, size_t data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    json::JSON del_json = json::JSON::Load_unsafe(reinterpret_cast<const uint8_t *>(data), data_size);
    long change = 0;

    if (del_json.JSONType() != json::JSON::Class::Object)
        return;

    for (auto item : del_json.ObjectRange())
    {
        change += item.second.ToInt();
    }

    // ----- Choose to be deleted hash ----- //
    SafeLock sl(wl->srd_mutex);
    sl.lock();
    // Get change hashs
    // Note: Cannot push srd hash pointer to vector because it will be deleted later
    std::vector<std::string> del_srds;
    if (wl->srd_hashs.size() > 0)
    {
        for (size_t i = wl->srd_hashs.size() - 1; i >= 0 && change > 0; i--)
        {
            std::string uuid = hexstring_safe(wl->srd_hashs[i], UUID_LENGTH);
            if (del_json[uuid].ToInt() > 0)
            {
                del_srds.push_back(hexstring_safe(wl->srd_hashs[i], SRD_LENGTH));
                wl->add_srd_to_deleted_buffer(i);
                del_json[uuid].AddNum(-1);
                change--;
            }
        }
    }
    sl.unlock();

    // Delete srd files
    if (del_srds.size() > 0)
    {
        for (auto srd : del_srds)
        {
            ocall_delete_folder_or_file(&crust_status, srd.c_str(), STORE_TYPE_SRD);
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", srd.c_str(), crust_status);
            }
        }
    }

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    ocall_set_srd_info(reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());
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
 * @param real_change -> Pointer to real changed srd number
 * @return: Changing return status
 */
crust_status_t change_srd_task(long change, long *real_change)
{
    Workload *wl = Workload::get_instance();
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
    // Set srd remaining task
    wl->set_srd_remaining_task(g_srd_task);
    sgx_thread_mutex_unlock(&g_srd_task_mutex);

    *real_change = change;

    // Update srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    ocall_set_srd_info(reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());

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
