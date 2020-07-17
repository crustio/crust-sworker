#include "Enclave.h"
#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "Workload.h"

using namespace std;

//------------------Srd ecalls-----------------//

/**
 * @description: seal one G srd files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void ecall_srd_increase(const char* path)
{
    srd_increase(path);
}

/**
 * @description: decrease srd files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
size_t ecall_srd_decrease(long change)
{
    return srd_decrease(change);
}

/**
 * @description: Change srd number
 * @param change -> Will be changed srd number
 * */
void ecall_srd_set_change(long change)
{
    long srd_change = get_srd_change() + change;
    set_srd_change(srd_change);
}

/**
 * @description: Update srd_path2hashs_m
 * @param hashs -> Pointer to the address of to be deleted hashs array
 * @param hashs_len -> Hashs array length
 * */
void ecall_srd_update_metadata(const char *hashs, size_t hashs_len)
{
    return srd_update_metadata(hashs, hashs_len);
}

/**
 * @description: ecall main loop
 */
void ecall_main_loop()
{
    while (true)
    {
        crust_status_t crust_status = CRUST_SUCCESS;

        // ----- Delete meaningful file ----- //
        storage_delete_file_real();

        // ----- Confirm meaningful file ----- //
        storage_confirm_file_real();

        // ----- Meaningful validate ----- //
        validate_meaningful_file();

        // ----- SRD validate ----- //
        validate_srd();

        // ----- SRD ----- //
        srd_change();

        // Store metadata periodically
        if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
        {
            log_err("Store enclave data failed!Error code:%lx\n", crust_status);
        }

        // Add validated proof
        report_add_validated_proof();

        ocall_usleep(MAIN_LOOP_WAIT_TIME);
    }
}

/**
 * @description: Restore enclave data from file
 * @return: Restore status
 * */
crust_status_t ecall_restore_metadata()
{
    return id_restore_metadata();
}

/**
 * @description: Compare chain account with enclave's
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 * @return: Compare status
 * */
crust_status_t ecall_cmp_chain_account_id(const char *account_id, size_t len)
{
    return id_cmp_chain_account_id(account_id, len);
}

/**
 * @description: Set crust account id
 * @param account_id (in) -> Pointer to account id
 * @param len -> Account id length
 * @return: Set status
 * */
crust_status_t ecall_set_chain_account_id(const char *account_id, size_t len)
{
    return id_set_chain_account_id(account_id, len);
}

/**
 * @description: Get signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @param p_signature (out) -> sig by tee
 * @param report (out) -> work report string
 * @param report_len (in) -> work report string length
 * @return: sign status
 * */
crust_status_t ecall_get_signed_work_report(const char *block_hash, size_t block_height)
{
    return get_signed_work_report(block_hash, block_height);
}

/**
 * @description: Get signed order report
 * @return: Get status
 * */
crust_status_t ecall_get_signed_order_report()
{
    return get_signed_order_report();
}

/**
 * @description: generate ecc key pair and store it in enclave
 * @return: generate status
 * */
sgx_status_t ecall_gen_key_pair()
{
    return id_gen_key_pair();
}

/**
 * @description: get sgx report, our generated public key contained
 *  in report data
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 * @return: get sgx report status
 * */
sgx_status_t ecall_get_quote_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
    return id_get_quote_report(report, target_info);
}

/**
 * @description: generate current code measurement
 * @return: generate status
 * */
sgx_status_t ecall_gen_sgx_measurement()
{
    return id_gen_sgx_measurement();
}

/**
 * @description: verify IAS report
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 * @return: verify status
 * */
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
 * */
crust_status_t ecall_seal_file(const char *p_tree, size_t tree_len, const char *path, char *p_new_path , size_t path_len)
{
    return storage_seal_file(p_tree, tree_len, path, path_len, p_new_path);
}

/**
 * @description: Unseal file according to given path
 * @param files (in) -> Files in root directory
 * @param files_num -> Files number in root directory
 * @param p_dir (in) -> Root directory path
 * @param p_new_path (out) -> Pointer to unsealed data path
 * @param path_len -> Root dir path length
 * @return: Unseal status
 * */
crust_status_t ecall_unseal_file(char **files, size_t files_num, const char *p_dir, char *p_new_path, uint32_t /*path_len*/)
{
    return storage_unseal_file(files, files_num, p_dir, p_new_path);
}

/**
 * @description: Confirm new file
 * @param hash -> New file hash
 * @return: Confirm status
 * */
void ecall_confirm_file(const char *hash)
{
    storage_confirm_file(hash);
}

/**
 * @description: Add to be deleted file hash to buffer
 * @param hash -> File root hash
 * */
void ecall_delete_file(const char *hash)
{
    return storage_delete_file(hash);
}

/**
 * @description: Get enclave id information
 * */
void ecall_id_get_info()
{
    id_get_info();
}

/**
 * @description: Get workload
 * */
void ecall_get_workload()
{
    Workload::get_instance()->get_workload();
}
