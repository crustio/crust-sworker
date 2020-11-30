#include "Enclave.h"
#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "Workload.h"

using namespace std;

/**
 * @description: Seal one G srd files under directory, can be called from multiple threads
 * @param path (in) -> the directory path
 */
void ecall_srd_increase(const char* path)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    sched_add(SCHED_SRD_CHANGE);
    srd_increase(path);
    sched_del(SCHED_SRD_CHANGE);
}

/**
 * @description: Decrease srd files under directory
 * @param change -> reduction
 * @return: Deleted srd space
 */
size_t ecall_srd_decrease(long change)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return 0;
    }

    sched_add(SCHED_SRD_CHANGE);
    size_t ret = srd_decrease(change);
    sched_del(SCHED_SRD_CHANGE);

    return ret;
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 */
crust_status_t ecall_change_srd_task(long change, long *real_change)
{
    return change_srd_task(change, real_change);
}

/**
 * @description: Update srd_path2hashs_m
 * @param hashs (in) -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 */
void ecall_srd_update_metadata(const char *hashs, size_t hashs_len)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    sched_add(SCHED_SRD_CHECK_RESERVED);
    srd_update_metadata(hashs, hashs_len);
    sched_del(SCHED_SRD_CHECK_RESERVED);
}

/**
 * @description: Ecall main loop
 */
void ecall_main_loop()
{
    Workload *wl = Workload::get_instance();

    while (true)
    {
        crust_status_t crust_status = CRUST_SUCCESS;

        if (ENC_UPGRADE_STATUS_SUCCESS == wl->get_upgrade_status())
        {
            break;
        }

        // ----- File validate ----- //
        sched_add(SCHED_VALIDATE_FILE);
        validate_meaningful_file();
        sched_del(SCHED_VALIDATE_FILE);

        // ----- SRD validate ----- //
        sched_add(SCHED_VALIDATE_SRD);
        validate_srd();
        sched_del(SCHED_VALIDATE_SRD);

        // ----- SRD ----- //
        sched_add(SCHED_SRD_CHANGE);
        srd_change();
        sched_del(SCHED_SRD_CHANGE);

        // Store metadata periodically
        if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
        {
            log_err("Store enclave data failed!Error code:%lx\n", crust_status);
        }

        // Add validated proof
        wl->report_add_validated_proof();

        ocall_usleep(MAIN_LOOP_WAIT_TIME);
    }
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
 * @param block_height (in) -> block height
 * @return: Sign status
 */
crust_status_t ecall_gen_and_upload_work_report(const char *block_hash, size_t block_height)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_GET_WORKREPORT);
    crust_status_t ret = gen_and_upload_work_report(block_hash, block_height, 0, false);
    sched_del(SCHED_GET_WORKREPORT);

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

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param cid (in) -> Pointer to ipfs content id
 * @return: Seal status
 */
crust_status_t ecall_seal_file(const char *cid)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_SEAL);
    crust_status_t ret = storage_seal_file(cid);
    sched_del(SCHED_SEAL);

    return ret;
}

/**
 * @description: Unseal file according to given path
 * @param data (in) -> Pointer to sealed data
 * @return: Unseal status
 */
crust_status_t ecall_unseal_file(const char *data, size_t data_size)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_UNSEAL);
    crust_status_t ret = storage_unseal_file(data, data_size);
    sched_del(SCHED_UNSEAL);

    return ret;
}

/**
 * @description: Add to be deleted file hash to buffer
 * @param hash (in) -> File root hash
 * @return: Delete status
 */
crust_status_t ecall_delete_file(const char *cid)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_DELETE_FILE);
    crust_status_t ret = storage_delete_file(cid);
    sched_del(SCHED_DELETE_FILE);

    return ret;
}

/**
 * @description: Check if upgrade can be done right now
 * @param block_height -> Current block height
 * @return: Capability to upgrade
 */
crust_status_t ecall_enable_upgrade(size_t block_height)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    if (CRUST_SUCCESS == (crust_status = wl->try_report_work(block_height)))
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
 * @param meta (in) -> Metadata from old version
 * @param meta_len -> Metadata length
 * @param total_size -> Total size of metadata data
 * @param transfer_end -> Indicate whether transfer is end
 * @return: Restore result
 */
crust_status_t ecall_restore_from_upgrade(const char *meta, size_t meta_len, size_t total_size, bool transfer_end)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    return id_restore_from_upgrade(meta, meta_len, total_size, transfer_end);
}

/**
 * @description: Get enclave id information
 */
void ecall_id_get_info()
{
    id_get_info();
}

/**
 * @description: Get workload
 */
void ecall_get_workload()
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    Workload::get_instance()->get_workload();
}
