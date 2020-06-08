#include "Enclave.h"
#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"

using namespace std;

/* Used to store validation status */
validation_status_t validation_status = VALIDATE_STOP;

//------------------Srd ecalls-----------------//

/**
 * @description: seal one G empty files under directory, can be called from multiple threads
 * @param path -> the directory path
 */
void ecall_srd_increase_empty(const char* path)
{
    srd_increase_empty(path);
}

/**
 * @description: decrease empty files under directory
 * @param path -> the directory path
 * @param change -> reduction
 */
size_t ecall_srd_decrease_empty(const char* path, size_t change)
{
    return srd_decrease_empty(path, change);
}

/**
 * @description: ecall main loop
 * @param empty_path -> the empty directory path
 */
void ecall_main_loop(const char *empty_path)
{
    while (true)
    {
        crust_status_t crust_status = CRUST_SUCCESS;

        // ----- Meaningful ----- //
        log_debug("----- Meaningful Validation -----\n");
        validation_status = VALIDATE_MEANINGFUL;
        validate_meaningful_file();

        // ----- Empty ----- //
        log_debug("----- Empty Validation -----\n");
        validation_status = VALIDATE_EMPTY;
        validate_empty_disk(empty_path);

        // ----- Show result ----- //
        log_debug("----- Validation Waiting -----\n");
        Workload::get_instance()->show();

        // Store metadata periodically
        if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
        {
            log_err("Store enclave data failed!Error code:%lx\n", crust_status);
        }
        else
        {
            log_debug("Store enclave data successfully!\n");
        }

        validation_status = VALIDATE_WAITING;
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
 * @description: return validation status
 * @return: the validation status
 */
validation_status_t ecall_return_validation_status(void)
{
    return validation_status;
}

/**
 * @description: generate work report
 * @param report_len (out) -> report's length
 * @return: status
 */
crust_status_t ecall_generate_work_report(size_t *report_len)
{
    return generate_work_report(report_len);
}

/**
 * @description: get validation report
 * @param report (out) -> the validation report
 * @param report_len (in) -> the length of validation report
 * @return: status
 */
crust_status_t ecall_get_work_report(char *report, size_t report_len)
{
    return get_work_report(report, report_len);
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
crust_status_t ecall_get_signed_work_report(const char *block_hash, size_t block_height,
        sgx_ec256_signature_t *p_signature, char *report, size_t report_len)
{
    return get_signed_work_report(block_hash, block_height, p_signature, report, report_len);
}

/**
 * @description: Sign network entry information
 * @param p_partial_data (in) -> Partial data represented off chain node identity
 * @param data_size -> Partial data size
 * @param p_signature (out) -> Pointer to signature
 * @return: Sign status
 * */
crust_status_t ecall_sign_network_entry(const char *p_partial_data, uint32_t data_size,
        sgx_ec256_signature_t *p_signature)
{
    return id_sign_network_entry(p_partial_data, data_size, p_signature);
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
sgx_status_t ecall_get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
    return id_get_report(report, target_info);
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
 * @description: Store off-chain node quote and verify signature
 * @param quote (in) -> Pointer to quote
 * @param len -> Quote length
 * @param p_data (in) -> Original data to be verified
 * @param data_size -> Original data length
 * @param p_signature (in) -> Signature of p_data
 * @param p_account_id (in) -> Pointer to chain account id
 * @param account_id_sz -> Chain account id size
 * @return: Store status
 * */
crust_status_t ecall_store_quote(const char *quote, size_t len, const uint8_t *p_data, uint32_t data_size,
        sgx_ec256_signature_t *p_signature, const uint8_t *p_account_id, uint32_t account_id_sz)
{
    return id_store_quote(quote, len, p_data, data_size, p_signature, p_account_id, account_id_sz);
}

/**
 * @description: verify IAS report
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 * @param p_ensig (out) -> Pointer to entry network report signature
 * @return: verify status
 * */
crust_status_t ecall_verify_iasreport(char **IASReport, size_t len, sgx_ec256_signature_t *p_ensig)
{
    return id_verify_iasreport(IASReport, len, p_ensig);
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
