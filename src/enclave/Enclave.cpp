#include "Enclave.h"
#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "Workload.h"

using namespace std;

/**
 * @description: Seal one G srd files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void ecall_srd_increase(const char* path)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
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
    sched_add(SCHED_SRD_CHANGE);
    size_t ret = srd_decrease(change);
    sched_del(SCHED_SRD_CHANGE);

    return ret;
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 */
void ecall_srd_set_change(long change)
{
    long srd_change = get_srd_change() + change;
    set_srd_change(srd_change);
}

/**
 * @description: Update srd_path2hashs_m
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 */
void ecall_srd_update_metadata(const char *hashs, size_t hashs_len)
{
    sched_add(SCHED_SRD_CHECK_RESERVED);
    srd_update_metadata(hashs, hashs_len);
    sched_del(SCHED_SRD_CHECK_RESERVED);
}

/**
 * @description: Ecall main loop
 */
void ecall_main_loop()
{
    while (true)
    {
        crust_status_t crust_status = CRUST_SUCCESS;

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

        if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
        {
            break;
        }

        // Add validated proof
        report_add_validated_proof();

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
crust_status_t ecall_get_signed_work_report(const char *block_hash, size_t block_height)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_GET_WORKREPORT);
    crust_status_t ret = get_signed_work_report(block_hash, block_height);
    sched_del(SCHED_GET_WORKREPORT);

    return ret;
}

/**
 * @description: Get signed order report
 * @return: Get status
 */
crust_status_t ecall_get_signed_order_report()
{
    sched_add(SCHED_GET_ORDERREPORT);
    crust_status_t ret = get_signed_order_report();
    sched_del(SCHED_GET_ORDERREPORT);

    return ret;
}

/**
 * @description: Generate ecc key pair and store it in enclave
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
crust_status_t ecall_verify_iasreport(char **IASReport, size_t len)
{
    return id_verify_iasreport(IASReport, len);
}

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param p_tree (in) -> Pointer to MerkleTree json structure buffer 
 * @param tree_len -> MerkleTree json structure buffer length
 * @param path (in) -> Reference to file path
 * @param p_new_path (out) -> Pointer to sealed data path
 * @param path_len -> Pointer to file path length
 * @return: Seal status
 */
crust_status_t ecall_seal_file(const char *p_tree, size_t tree_len, const char *path, char *p_new_path , size_t path_len)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_SEAL);
    crust_status_t ret = storage_seal_file(p_tree, tree_len, path, path_len, p_new_path);
    sched_del(SCHED_SEAL);

    return ret;
}

/**
 * @description: Unseal file according to given path
 * @param files (in) -> Files in root directory
 * @param files_num -> Files number in root directory
 * @param p_dir (in) -> Root directory path
 * @param p_new_path (out) -> Pointer to unsealed data path
 * @param path_len -> Root dir path length
 * @return: Unseal status
 */
crust_status_t ecall_unseal_file(char **files, size_t files_num, const char *p_dir, char *p_new_path, uint32_t /*path_len*/)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_UNSEAL);
    crust_status_t ret = storage_unseal_file(files, files_num, p_dir, p_new_path);
    sched_del(SCHED_UNSEAL);

    return ret;
}

/**
 * @description: Confirm new file
 * @param hash -> New file hash
 * @return: Confirm status
 */
crust_status_t ecall_confirm_file(const char *hash)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_CONFIRM_FILE);
    crust_status_t ret = storage_confirm_file(hash);
    sched_del(SCHED_CONFIRM_FILE);

    return ret;
}

/**
 * @description: Add to be deleted file hash to buffer
 * @param hash -> File root hash
 * @return: Delete status
 */
crust_status_t ecall_delete_file(const char *hash)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    sched_add(SCHED_DELETE_FILE);
    crust_status_t ret = storage_delete_file(hash);
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
    if ((block_height != 0 && block_height - id_get_report_height() - WORKREPORT_REPORT_INTERVAL >= ERA_LENGTH)
            && report_has_validated_proof()
            && !id_just_after_restart()
            && Workload::get_instance()->get_report_flag())
    {
        Workload::get_instance()->set_upgrade_status(ENC_UPGRADE_STATUS_PROCESS);
        return CRUST_SUCCESS;
    }

    return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
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
 * @return: Generate result
 */
crust_status_t ecall_gen_upgrade_data(size_t block_height)
{
    return id_gen_upgrade_data(block_height);
}

/**
 * @description: Restore from upgrade data
 * @param meta -> Metadata from old version
 * @param meta_len -> Metadata length
 * @return: Restore result
 */
crust_status_t ecall_restore_from_upgrade(const char *meta, size_t meta_len, size_t total_size, bool transfer_end)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    return id_restore_from_upgrade(meta, meta_len, total_size, transfer_end);
}

/**
 * @description: Set work report result
 * @param flag -> Report result
 */
void ecall_handle_report_result()
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    Workload::get_instance()->handle_report_result();
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
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    Workload::get_instance()->get_workload();
}
