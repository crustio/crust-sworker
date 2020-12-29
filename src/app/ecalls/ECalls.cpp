#include "ECalls.h"

EnclaveQueue *eq = EnclaveQueue::get_instance();

/**
 * @description: A wrapper function, seal one G srd files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
sgx_status_t Ecall_srd_increase(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_increase(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, decrease srd files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
sgx_status_t Ecall_srd_decrease(sgx_enclave_id_t eid, size_t *size, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_decrease(eid, size, change);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, ecall main loop
 */
sgx_status_t Ecall_main_loop(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_main_loop(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, ecall stop all
 */
sgx_status_t Ecall_stop_all(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_stop_all(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Restore enclave data from file
 * @param status -> Pointer to restore result status
 */
sgx_status_t Ecall_restore_metadata(sgx_enclave_id_t eid, crust_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_restore_metadata(eid, status);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Compare chain account with enclave's
 * @param status -> Pointer to compare result status
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 */
sgx_status_t Ecall_cmp_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_cmp_chain_account_id(eid, status, account_id, len);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Get signed validation report
 * @param status -> Pointer to get result status
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 */
sgx_status_t Ecall_gen_and_upload_work_report(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_and_upload_work_report(eid, status, block_hash, block_height);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate ecc key pair and store it in enclave
 */
sgx_status_t Ecall_gen_key_pair(sgx_enclave_id_t eid, sgx_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_key_pair(eid, status, account_id, len);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, get sgx report, our generated public key contained
 *  in report data
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 */
sgx_status_t Ecall_get_quote_report(sgx_enclave_id_t eid, sgx_status_t *status, sgx_report_t *report, sgx_target_info_t *target_info)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_quote_report(eid, status, report, target_info);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate current code measurement
 */
sgx_status_t Ecall_gen_sgx_measurement(sgx_enclave_id_t eid, sgx_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_sgx_measurement(eid, status);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, verify IAS report
 * @param status -> Pointer to verify result status
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 */
sgx_status_t Ecall_verify_and_upload_identity(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_verify_and_upload_identity(eid, status, IASReport, len);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Seal file according to given path and return new MerkleTree
 * @param status -> Pointer to seal result status
 * @param cid -> Ipfs content id
 * @param file_size -> Pointer to sealed file size
 */
sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *cid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_seal_file(eid, status, cid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Unseal file according to given path
 * @param status -> Pointer to unseal result status
 * @param files (in) -> Files in root directory
 * @param files_num -> Files number in root directory
 * @param p_dir (in) -> Root directory path
 * @param p_new_path (out) -> Pointer to unsealed data path
 * @param path_len -> Root dir path length
 */
sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *data, size_t data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_unseal_file(eid, status, data, data_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 */
sgx_status_t Ecall_change_srd_task(sgx_enclave_id_t eid, crust_status_t *status, long change, long *real_change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_change_srd_task(eid, status, change, real_change);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Update srd_g_hashs
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 */
sgx_status_t Ecall_srd_remove_space(sgx_enclave_id_t eid, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_remove_space(eid, change);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Delete file
 * @param status -> Pointer to delete result status
 * @param hash -> File root hash
 */
sgx_status_t Ecall_delete_file(sgx_enclave_id_t eid, crust_status_t *status, const char *hash)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_delete_file(eid, status, hash);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Generate upgrade metadata
 * @param status -> Pointer to generate result status
 */
sgx_status_t Ecall_gen_upgrade_data(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_upgrade_data(eid, status, block_height);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Generate upgrade metadata
 * @param status -> Pointer to metadata
 */
sgx_status_t Ecall_restore_from_upgrade(sgx_enclave_id_t eid, crust_status_t *status, const char *meta, size_t meta_len, size_t total_size, bool transfer_end)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_restore_from_upgrade(eid, status, meta, meta_len, total_size, transfer_end);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Enable upgrade
 * @param block_height -> Current block height
 */
sgx_status_t Ecall_enable_upgrade(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_enable_upgrade(eid, status, block_height);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Disable upgrade
 */
sgx_status_t Ecall_disable_upgrade(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_disable_upgrade(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get enclave id information
 */
sgx_status_t Ecall_id_get_info(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_id_get_info(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get workload
 */
sgx_status_t Ecall_get_workload(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_workload(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}
