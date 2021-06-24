#include "SrdTest.h"

extern long g_srd_task;
extern sgx_thread_mutex_t g_srd_task_mutex;

void srd_change_test(long change, bool real)
{
    // Set srd change number
    long real_change = 0;
    change_srd_task(change, &real_change);

    // ----- Do srd change ----- //
    Workload *wl = Workload::get_instance();
    if (ENC_UPGRADE_STATUS_SUCCESS == wl->get_upgrade_status())
    {
        return;
    }
    sgx_thread_mutex_lock(&g_srd_task_mutex);
    long tmp_g_srd_task = g_srd_task;
    g_srd_task = 0;
    sgx_thread_mutex_unlock(&g_srd_task_mutex);
    // Srd loop
    while (tmp_g_srd_task != 0)
    {
        // Get real srd space
        long srd_change_num = 0;
        if (tmp_g_srd_task > SRD_MAX_INC_PER_TURN)
        {
            srd_change_num = SRD_MAX_INC_PER_TURN;
            tmp_g_srd_task -= SRD_MAX_INC_PER_TURN;
        }
        else
        {
            srd_change_num = tmp_g_srd_task;
            tmp_g_srd_task = 0;
        }
        // Do srd
        crust_status_t crust_status = CRUST_SUCCESS;
        if (srd_change_num != 0)
        {
            if (real)
            {
                ocall_srd_change(&crust_status, srd_change_num);
            }
            else
            {
                ocall_srd_change_test(&crust_status, srd_change_num);
            }
            if (CRUST_SRD_NUMBER_EXCEED == crust_status)
            {
                sgx_thread_mutex_lock(&g_srd_task_mutex);
                g_srd_task = 0;
                sgx_thread_mutex_unlock(&g_srd_task_mutex);
            }
        }
        // Update srd info
        std::string srd_info_str = wl->get_srd_info().dump();
        ocall_set_srd_info(reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size());
    }
}

crust_status_t srd_increase_test(const char *uuid)
{
    Workload *wl = Workload::get_instance();

    // Get uuid bytes
    uint8_t *p_uuid_u = hex_string_to_bytes(uuid, UUID_LENGTH * 2);
    if (p_uuid_u == NULL)
    {
        log_err("Get uuid bytes failed! Invalid uuid:%s\n", uuid);
        return CRUST_UNEXPECTED_ERROR;
    }
    Defer def_uuid([&p_uuid_u](void) { free(p_uuid_u); });

    // Generate base random data

    // Generate current G hash index

    // ----- Generate srd file ----- //
    // Create directory

    // Generate all M hashs and store file to disk
    uint8_t *m_hashs = (uint8_t *)enc_malloc(HASH_LENGTH);
    if (m_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    Defer defer_hashs([&m_hashs](void) { free(m_hashs); });
    memset(m_hashs, 0, HASH_LENGTH);
    sgx_read_rand(m_hashs, HASH_LENGTH);

    // Generate G hashs
    sgx_sha256_hash_t g_hash;
    sgx_sha256_msg(m_hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_hash);

    // Change G path name
    std::string g_hash_hex = hexstring_safe(&g_hash, HASH_LENGTH);
    // ----- Update srd_hashs ----- //
    // Add new g_hash to srd_hashs
    // Because add this p_hash_u to the srd_hashs, so we cannot free p_hash_u
    uint8_t *srd_item = (uint8_t *)enc_malloc(SRD_LENGTH);
    if (srd_item == NULL)
    {
        log_err("Malloc for srd item failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(srd_item, 0, SRD_LENGTH);
    memcpy(srd_item, p_uuid_u, UUID_LENGTH);
    memcpy(srd_item + UUID_LENGTH, g_hash, HASH_LENGTH);
    sgx_thread_mutex_lock(&wl->srd_mutex);
    wl->srd_hashs.push_back(srd_item);
    log_info("Seal random data -> %s, %luG success\n", g_hash_hex.c_str(), wl->srd_hashs.size());
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(uuid, 1);

    return CRUST_SUCCESS;
}

size_t srd_decrease_test(size_t change)
{
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

    return change;
}
