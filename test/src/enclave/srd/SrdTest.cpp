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
        if (tmp_g_srd_task > SRD_MAX_PER_TURN)
        {
            srd_change_num = SRD_MAX_PER_TURN;
            tmp_g_srd_task -= SRD_MAX_PER_TURN;
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
        if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
        {
            log_warn("Set srd info failed! Error code:%lx\n", crust_status);
        }
    }
}

void srd_increase_test()
{
    Workload *wl = Workload::get_instance();

    // Generate base random data

    // Generate current G hash index
    char tmp_val[16];
    sgx_read_rand((unsigned char *)&tmp_val, 16);
    std::string tmp_dir = hexstring_safe(tmp_val, 16);

    // ----- Generate srd file ----- //
    // Create directory

    // Generate all M hashs and store file to disk
    uint8_t hashs[HASH_LENGTH];
    sgx_read_rand(hashs, HASH_LENGTH);

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, HASH_LENGTH, &g_out_hash256);

    // Change G path name

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

size_t srd_decrease_test(size_t change)
{
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
    std::vector<size_t> srd_del_indexes;
    for (size_t i = 1; i <= change; i++)
    {
        size_t index = wl->srd_hashs.size() - i;
        srd_del_indexes.push_back(index);
    }
    std::reverse(srd_del_indexes.begin(), srd_del_indexes.end());
    long r_change = -(long)change;
    wl->set_srd_info(r_change);
    wl->delete_srd_meta(srd_del_indexes);
    sl.unlock();

    // Delete srd files

    return change;
}
