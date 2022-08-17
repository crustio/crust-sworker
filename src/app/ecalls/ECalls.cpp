#include "ECalls.h"

EnclaveQueue *eq = EnclaveQueue::get_instance();

/**
 * @description: A wrapper function, seal one G srd files under directory, can be called from multiple threads
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to restore result status
 * @param uuid (in) -> Pointer to disk uuid
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_srd_increase(sgx_enclave_id_t eid, crust_status_t *status, const char *uuid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_increase(eid, status, uuid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, decrease srd files under directory
 * @param eid -> Enclave id
 * @param size (out) -> Pointer to decreased srd size
 * @param change -> reduction
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to restore result status
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to compare result status
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to get result status
 * @param block_hash (in) -> block hash
 * @param block_height -> block height
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param account_id (in) -> Pointer to account id
 * @param len -> Account id length
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to verify result status
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_upload_epid_identity(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_upload_epid_identity(eid, status, IASReport, len);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Get ECDSA identity
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to verify result status
 * @param p_quote (in) -> Pointer to quote buffer
 * @param quote_size -> Quote buffer size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_upload_ecdsa_quote(sgx_enclave_id_t eid, crust_status_t *status, uint8_t *p_quote, uint32_t quote_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_upload_ecdsa_quote(eid, status, p_quote, quote_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Get ECDSA identity
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to verify result status
 * @param p_quote (in) -> Pointer to quote buffer
 * @param quote_size -> Quote buffer size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_upload_ecdsa_identity(sgx_enclave_id_t eid, crust_status_t *status, const char *report, uint32_t size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_upload_ecdsa_identity(eid, status, report, size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, seal file start
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to seal result status
 * @param cid (in) -> Pointer to file root cid
 * @param cid_b58 cid (in) -> root cid b58 format
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_seal_file_start(sgx_enclave_id_t eid, crust_status_t *status, const char *cid, const char *cid_b58)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_seal_file_start(eid, status, cid, cid_b58);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Seal file according to given path and return new MerkleTree
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to seal result status
 * @param cid (in) -> Ipfs content id
 * @param data (in) -> Pointer to raw data or link
 * @param data_size -> Raw data size or link size
 * @param is_link -> Indicate data is raw data or a link
 * @param path (in, out) -> Index path used to get file block
 * @param path_size -> Index path size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid,
                             crust_status_t *status,
                             const char *cid,
                             const uint8_t *data,
                             size_t data_size,
                             bool is_link,
                             char *path,
                             size_t path_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_seal_file(eid, status, cid, data, data_size, is_link, path, path_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, seal file end
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to seal result status
 * @param cid (in) -> Pointer to file root cid
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_seal_file_end(sgx_enclave_id_t eid, crust_status_t *status, const char *cid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_seal_file_end(eid, status, cid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Unseal file according to given path
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to unseal result status
 * @param path (in) -> Pointer to file block stored path
 * @param p_decrypted_data -> Pointer to decrypted data buffer
 * @param decrypted_data_size -> Decrypted data buffer size
 * @param p_decrypted_data_size -> Pointer to decrypted data real size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *path, uint8_t *p_decrypted_data, size_t decrypted_data_size, size_t *p_decrypted_data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_unseal_file(eid, status, path, p_decrypted_data, decrypted_data_size, p_decrypted_data_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Change srd number
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param change -> Will be changed srd number
 * @param real_change (out) -> Pointer to real changed srd size
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param data -> Pointer to deleted srd info
 * @param data_size -> Data size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_srd_remove_space(sgx_enclave_id_t eid, const char *data, size_t data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_remove_space(eid, data, data_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Delete file
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to delete result status
 * @param hash (in) -> File root hash
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to generate result status
 * @param block_height -> Chain block height
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param data (in) -> Pointer to metadata
 * @param data_size -> Meta length
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_restore_from_upgrade(sgx_enclave_id_t eid, crust_status_t *status, const uint8_t *data, size_t data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_restore_from_upgrade(eid, status, data, data_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Enable upgrade
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param block_height -> Current block height
 * @return: Invoking ecall return status
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
 * @description: Validate meaningful files
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Validate srd
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_srd(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Disable upgrade
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
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
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
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
 * @description: Enable upgrade
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param data (in) -> Pointer to recover data
 * @param data_size -> Recover data size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_recover_illegal_file(sgx_enclave_id_t eid, crust_status_t *status, const uint8_t *data, size_t data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_recover_illegal_file(eid, status, data, data_size);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Safe store large data to enclave
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param t -> Ecall store function type
 * @param data (in) -> Pointer to data
 * @param total_size -> Total data size
 * @param partial_size -> Current store data size
 * @param offset -> Offset in total data
 * @param buffer_key -> Session key for this time enclave data store
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_safe_store2(sgx_enclave_id_t eid,
                               crust_status_t *status,
                               ecall_store_type_t t,
                               const uint8_t *data,
                               size_t total_size,
                               size_t partial_size,
                               size_t offset,
                               uint32_t buffer_key)
{
    sgx_status_t ret = SGX_SUCCESS;
    std::string func = eq->ecall_store2_func_m[t];
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(func.c_str())))
    {
        return ret;
    }

    ret = ecall_safe_store2(eid, status, t, data, total_size, partial_size, offset, buffer_key);

    eq->free_enclave(func.c_str());

    return ret;
}
