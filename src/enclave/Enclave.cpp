#include "Enclave.h"

using namespace std;

std::map<uint32_t, uint8_t *> g_ecall_buffer_pool;
sgx_thread_mutex_t g_ecall_buffer_pool_mutex = SGX_THREAD_MUTEX_INITIALIZER;
std::map<ecall_store_type_t, ecall_store2_f> g_ecall_store2_func_m = {
    {ECALL_RESTORE_FROM_UPGRADE, ecall_restore_from_upgrade},
};

/**
 * @description: Ecall main loop
 */
void ecall_main_loop()
{
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;

    while (true)
    {
        if (ENC_UPGRADE_STATUS_SUCCESS == wl->get_upgrade_status())
        {
            log_info("Stop enclave main loop for exit...\n");
            return;
        }

        // Store metadata periodically
        log_debug("Start storing metadata\n");
        if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
        {
            log_err("Store enclave data failed! Error code:%lx\n", crust_status);
        }

        // ----- File validate ----- //
        log_debug("Start validating meaningful file\n");
        validate_meaningful_file();

        // ----- SRD validate ----- //
        log_debug("Start validating srd\n");
        validate_srd();

        // ----- SRD ----- //
        log_debug("Start srd task\n");
        srd_change();

        // Wait
        for (size_t i = 0; i < MAIN_LOOP_WAIT_TIME; i++)
        {
            if (ENC_UPGRADE_STATUS_SUCCESS == wl->get_upgrade_status())
            {
                log_info("Stop enclave main loop for exit...\n");
                return;
            }
            ocall_usleep(1000000);
        }
    }
}

/************************************SRD****************************************/

/**
 * @description: Seal one G srd files under directory, can be called from multiple threads
 * @param uuid (in) -> Disk path uuid
 * @return: Srd increase result
 */
crust_status_t ecall_srd_increase(const char *uuid)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    return srd_increase(uuid);
}

/**
 * @description: Decrease srd files under directory
 * @param change -> reduction
 * @return: Deleted srd space
 */
size_t ecall_srd_decrease(size_t change)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return 0;
    }

    size_t ret = srd_decrease(change);

    return ret;
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 * @param real_change (out) -> Pointer to real changed srd task number
 * @return: Changing result status
 */
crust_status_t ecall_change_srd_task(long change, long *real_change)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    return change_srd_task(change, real_change);
}

/**
 * @description: Update srd_metadata
 * @param data (in) -> Pointer to deleted srd info
 * @param data_size -> Data size
 */
void ecall_srd_remove_space(const char *data, size_t data_size)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    srd_remove_space(data, data_size);
}

/************************************System****************************************/

/**
 * @description: Stop enclave
 */
void ecall_stop_all()
{
    Workload::get_instance()->set_upgrade_status(ENC_UPGRADE_STATUS_SUCCESS);
    id_store_metadata();
}

/**
 * @description: Restore enclave data from file
 * @return: Restore status
 */
crust_status_t ecall_restore_metadata()
{
    return id_restore_metadata();
}

/**
 * @description: Compare chain account with enclave's
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 * @return: Compare status
 */
crust_status_t ecall_cmp_chain_account_id(const char *account_id, size_t len)
{
    return id_cmp_chain_account_id(account_id, len);
}

/**
 * @description: Get signed work report
 * @param block_hash (in) -> block hash
 * @param block_height -> block height
 * @return: Sign status
 */
crust_status_t ecall_gen_and_upload_work_report(const char *block_hash, size_t block_height)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    crust_status_t ret = gen_and_upload_work_report(block_hash, block_height, 0, false, true);

    return ret;
}

/**
 * @description: Generate ecc key pair and store it in enclave
 * @param account_id (in) -> Chain account id
 * @param len -> Chain account id length
 * @return: Generate status
 */
sgx_status_t ecall_gen_key_pair(const char *account_id, size_t len)
{
    return id_gen_key_pair(account_id, len);
}

/**
 * @description: Get sgx report, our generated public key contained
 *  in report data
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 * @return: Get sgx report status
 */
sgx_status_t ecall_get_quote_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
    return id_get_quote_report(report, target_info);
}

/**
 * @description: Generate current code measurement
 * @return: Generate status
 */
sgx_status_t ecall_gen_sgx_measurement()
{
    return id_gen_sgx_measurement();
}

/**
 * @description: Verify IAS report
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 * @return: Verify status
 */
crust_status_t ecall_verify_and_upload_identity(char **IASReport, size_t len)
{
    return id_verify_and_upload_identity(IASReport, len);
}

/************************************Files****************************************/

/**
 * @description: IPFS informs sWorker to prepare for seal
 * @param root (in) -> File root cid
 * @return: Inform result
 */
crust_status_t ecall_seal_file_start(const char *root)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    crust_status_t ret = storage_seal_file_start(root);

    return ret;
}

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param root (in) -> Pointer to file root cid
 * @param data (in) -> Pointer to raw data or link
 * @param data_size -> Raw data size or link size
 * @param is_link -> Indicate data is raw data or a link
 * @param path (in, out) -> Index path used to get file block
 * @param path_size -> Index path size
 * @return: Seal status
 */
crust_status_t ecall_seal_file(const char *root,
                               const uint8_t *data,
                               size_t data_size,
                               bool is_link,
                               char *path,
                               size_t path_size)
{
    return storage_seal_file(root, data, data_size, is_link, path, path_size);
}

/**
 * @description: IPFS informs sWorker seal end
 * @param root (in) -> File root cid
 * @return: Inform result
 */
crust_status_t ecall_seal_file_end(const char *root)
{
    return storage_seal_file_end(root);
}

/**
 * @description: Unseal file according to given path
 * @param path (in) -> Pointer to file block stored path
 * @param p_decrypted_data (in) -> Pointer to decrypted data buffer
 * @param decrypted_data_size -> Decrypted data buffer size
 * @param p_decrypted_data_size -> Pointer to decrypted data real size
 * @return: Unseal status
 */
crust_status_t ecall_unseal_file(const char *path, uint8_t *p_decrypted_data, size_t decrypted_data_size, size_t *p_decrypted_data_size)
{
    crust_status_t ret = storage_unseal_file(path, p_decrypted_data, decrypted_data_size, p_decrypted_data_size);

    return ret;
}

/**
 * @description: Add to be deleted file hash to buffer
 * @param cid (in) -> File content id
 * @return: Delete status
 */
crust_status_t ecall_delete_file(const char *cid)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    crust_status_t ret = storage_delete_file(cid);

    return ret;
}

/**
 * @description: Validate meaningful files
 */
void ecall_validate_file()
{
    validate_meaningful_file_real();
}

/**
 * @description: Validate srd
 */
void ecall_validate_srd()
{
    validate_srd_real();
}

/************************************Upgrade****************************************/

/**
 * @description: Check if upgrade can be done right now
 * @param block_height -> Current block height
 * @return: Capability to upgrade
 */
crust_status_t ecall_enable_upgrade(size_t block_height)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    if (CRUST_SUCCESS == (crust_status = wl->can_report_work(block_height)))
    {
        wl->set_upgrade_status(ENC_UPGRADE_STATUS_PROCESS);
    }

    return crust_status;
}

/**
 * @description: Disable is_upgrading
 */
void ecall_disable_upgrade()
{
    Workload::get_instance()->set_upgrade_status(ENC_UPGRADE_STATUS_NONE);
}


/**
 * @description: Generate upgrade data
 * @param block_height -> Current block height
 * @return: Generate result
 */
crust_status_t ecall_gen_upgrade_data(size_t block_height)
{
    return id_gen_upgrade_data(block_height);
}

/**
 * @description: Restore from upgrade data
 * @param data (in) -> Metadata from old version
 * @param data_size -> Metadata length
 * @return: Restore result
 */
crust_status_t ecall_restore_from_upgrade(const uint8_t *data, size_t data_size)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    return id_restore_from_upgrade(data, data_size);
}

/**
 * @description: Deal with file illegal transfer
 * @param data (in) -> Pointer to recover data
 * @param data_size -> Recover data size
 * @return: Recover status
 */
crust_status_t ecall_recover_illegal_file(const uint8_t *data, size_t data_size)
{
    return Workload::get_instance()->recover_illegal_file(data, data_size);
}

/************************************Tools****************************************/

/**
 * @description: Get enclave id information
 */
void ecall_id_get_info()
{
    id_get_info();
}

/**
 * @description: Ecall save big data
 * @param t -> Store function type
 * @param data (in) -> Pointer to data
 * @param total_size -> Total data size
 * @param partial_size -> Current store data size
 * @param offset -> Offset in total data
 * @param buffer_key -> Session key for this time enclave data store
 * @return: Store result
 */
crust_status_t ecall_safe_store2(ecall_store_type_t t,
                                 const uint8_t *data,
                                 size_t total_size,
                                 size_t partial_size,
                                 size_t offset,
                                 uint32_t buffer_key)
{
    SafeLock sl(g_ecall_buffer_pool_mutex);
    sl.lock();
    crust_status_t crust_status = CRUST_SUCCESS;
    bool is_end = true;
    if (offset < total_size)
    {
        uint8_t *buffer = NULL;
        if (g_ecall_buffer_pool.find(buffer_key) != g_ecall_buffer_pool.end())
        {
            buffer = g_ecall_buffer_pool[buffer_key];
        }
        if (buffer == NULL)
        {
            buffer = (uint8_t *)malloc(total_size);
            if (buffer == NULL)
            {
                crust_status = CRUST_MALLOC_FAILED;
                goto cleanup;
            }
            memset(buffer, 0, total_size);
            g_ecall_buffer_pool[buffer_key] = buffer;
        }
        memcpy(buffer + offset, data, partial_size);
        if (offset + partial_size < total_size)
        {
            is_end = false;
        }
    }

    if (!is_end)
    {
        return CRUST_SUCCESS;
    }

    crust_status = (g_ecall_store2_func_m[t])(g_ecall_buffer_pool[buffer_key], total_size);

cleanup:

    if (g_ecall_buffer_pool.find(buffer_key) != g_ecall_buffer_pool.end())
    {
        free(g_ecall_buffer_pool[buffer_key]);
        g_ecall_buffer_pool.erase(buffer_key);
    }

    return crust_status;
}
