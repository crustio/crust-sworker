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
        log_debug("-----Meaningful Validation-----\n");
        /* Meaningful */
        validation_status = VALIDATE_MEANINGFUL;
        crust_status_t crust_status = CRUST_SUCCESS;
        Node *diff_files = NULL;
        ocall_get_diff_files(&diff_files);
        size_t diff_files_num = 0;
        ocall_get_diff_files_num(&diff_files_num);
        validate_meaningful_disk(diff_files, diff_files_num);

        log_debug("-----Empty Validation-----\n");
        /* Empty */
        validation_status = VALIDATE_EMPTY;
        validate_empty_disk(empty_path);

        log_debug("-----Validation Waiting-----\n");
        /* Show result */
        Workload::get_instance()->show();

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
 * @param account_id -> Pointer to account id
 * @param len -> account id length
 * @return: Compare status
 * */
crust_status_t ecall_cmp_chain_account_id(const char *account_id, size_t len)
{
    return id_cmp_chain_account_id(account_id, len);
}

/**
 * @description: Set crust account id
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
 * @param p_partial_data -> Partial data represented off chain node identity
 * @param data_size -> Partial data size
 * @param p_signature -> Pointer to signature
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
 * @return: Store status
 * */
crust_status_t ecall_store_quote(const char *quote, size_t len, const uint8_t *p_data, uint32_t data_size,
        sgx_ec256_signature_t *p_signature, const uint8_t *p_account_id, uint32_t account_id_sz)
{
    return id_store_quote(quote, len, p_data, data_size, p_signature, p_account_id, account_id_sz);
}

/**
 * @description: verify IAS report
 * @param IASReport -> Vector first address
 * @param len -> Count of Vector IASReport
 * @param p_ensig -> Pointer to entry network report signature
 * @return: verify status
 * */
crust_status_t ecall_verify_iasreport(char **IASReport, size_t len, entry_network_signature *p_ensig)
{
    return id_verify_iasreport(IASReport, len, p_ensig);
}

/**
 * @description: Validate merkle tree and storage tree related meta data
 * @param root_hash -> Merkle tree root hash
 * @param hash_len -> Merkle tree root hash length
 * @return: Validate status
 * */
crust_status_t ecall_validate_merkle_tree(MerkleTree **root)
{
    return storage_validate_merkle_tree(*root);
}

/**
 * @description: Seal file according to given path and return new MerkleTree
 * @param root -> MerkleTree root node
 * @param path -> Reference to file path
 * @param tree -> New MerkleTree
 * @return: Seal status
 * */
crust_status_t ecall_seal_file(MerkleTree **root, const char *path, size_t path_len)
{
    return storage_seal_file(*root, path, path_len);
}

/**
 * @description: Unseal file according to given path
 * @param p_dir -> Root directory path
 * @param dir_len -> Root dir path length
 * @param files -> Files in root directory
 * @param files_num -> Files number in root directory
 * @return: Unseal status
 * */
crust_status_t ecall_unseal_file(char **files, size_t files_num, const char *p_dir)
{
    return storage_unseal_file(files, files_num, p_dir);
}

/**
 * @description: Seal file block and generate new tree
 * @param root_hash -> file root hash
 * @param root_hash_len -> file root hash lenght
 * @param path -> path from root node to file block node
 * @param path_count -> path vector size
 * @param p_src -> pointer to file block data
 * @param src_len -> file block data size
 * @param p_sealed_data -> sealed file block data
 * @param sealed_data_size -> sealed file block data size
 * @return: Seal and generate result
 * */
crust_status_t ecall_seal_data(const uint8_t *root_hash, uint32_t root_hash_len,
        const uint8_t *p_src, size_t src_len, uint8_t *p_sealed_data, size_t sealed_data_size)
{
    return storage_seal_data(root_hash, root_hash_len, p_src, src_len, p_sealed_data, sealed_data_size);
}

/**
 * @description: Unseal and verify file block data
 * @param p_sealed_data -> sealed file block data
 * @param sealed_data_size -> sealed file block data size
 * @param p_unsealed_data -> unsealed file block data
 * @param unsealed_data_size -> unsealed file block data size
 * @return: Unseal status
 * */
crust_status_t ecall_unseal_data(const uint8_t *p_sealed_data, size_t sealed_data_size,
        uint8_t *p_unsealed_data, uint32_t unsealed_data_size)
{
    return storage_unseal_data(p_sealed_data, sealed_data_size, p_unsealed_data, unsealed_data_size);
}

/**
 * @description: Generate validate Merkle hash tree after seal file successfully
 * @param root_hash -> root hash of Merkle tree
 * @param root_hash_len -> root hash length
 * @return: Generate status
 * */
crust_status_t ecall_gen_new_merkle_tree(const uint8_t *root_hash, uint32_t root_hash_len)
{
    return storage_gen_new_merkle_tree(root_hash, root_hash_len);
}
