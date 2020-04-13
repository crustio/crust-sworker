#include "Enclave.h"
#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"

using namespace std;

// TODO: Divide ecall into different files according to functions
/* Used to store validation status */
enum ValidationStatus validation_status = ValidateStop;

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
        log_info("-----Meaningful Validation-----\n");
        /* Meaningful */
        validation_status = ValidateMeaningful;
        crust_status_t crust_status = CRUST_SUCCESS;
        Node *diff_files = NULL;
        ocall_get_diff_files(&diff_files);
        size_t diff_files_num = 0;
        ocall_get_diff_files_num(&diff_files_num);
        validate_meaningful_disk(diff_files, diff_files_num);

        log_info("-----Empty Validation-----\n");
        /* Empty */
        validation_status = ValidateEmpty;
        srd_generate_empty_root();
        validate_empty_disk(empty_path);
        srd_generate_empty_root();

        log_info("-----Validation Waiting-----\n");
        /* Show result */
        validation_status = ValidateWaiting;
        get_workload()->show();

        if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
        {
            log_err("Store enclave data failed!Error code:%lx\n", crust_status);
        }
        else
        {
            log_info("Store enclave data successfully!\n");
        }

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
enum ValidationStatus ecall_return_validation_status(void)
{
    return validation_status;
}

/**
 * @description: generate validation report
 * @return: the length of validation report
 */
void ecall_generate_validation_report(size_t *size)
{
    *size = get_workload()->serialize().size() + 1;
}

/**
 * @description: get validation report
 * @param report(out) -> the validation report
 * @param len -> the length of validation report
 * @return: the validation report
 */
void ecall_get_validation_report(char *report, size_t len)
{
    std::copy(get_workload()->report.begin(), get_workload()->report.end(), report);
    report[len - 1] = '\0';
}

/**
 * @description: Get signed validation report
 * @param: block_hash(in) -> block hash
 * @param: block_height(in) -> block height
 * @param: p_signature(out) -> sig by tee
 * @param: report(out) -> work report string
 * @param: report_len(in) -> work report string length
 * @return: sign status
 * */
crust_status_t ecall_get_signed_validation_report(const char *block_hash, size_t block_height,
        sgx_ec256_signature_t *p_signature, char *report, size_t report_len)
{
    // Judge whether block height is expired
    if (block_height <= id_get_cwr_block_height())
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }
    else
    {
        id_set_cwr_block_height(block_height);
    }

    // Create signature data
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status_t sgx_status;
    Workload *wl = get_workload();
    size_t meaningful_workload_size = 0;
    for (auto it = wl->files.begin(); it != wl->files.end(); it++)
    {
        meaningful_workload_size += it->second;
    }
    unsigned long long tmpSize = wl->empty_disk_capacity;
    tmpSize = tmpSize * 1024 * 1024 * 1024;
    uint8_t *byte_buf = NULL;

    // Convert number type to string
    std::string block_height_str = std::to_string(block_height);
    std::string empty_disk_capacity_str = std::to_string(tmpSize);
    std::string meaningful_workload_size_str = std::to_string(meaningful_workload_size);
    uint8_t *block_height_u = (uint8_t *)malloc(block_height_str.size());
    uint8_t *empty_disk_capacity_u = (uint8_t *)malloc(empty_disk_capacity_str.size());
    uint8_t *meaningful_workload_size_u = (uint8_t *)malloc(meaningful_workload_size_str.size());
    memset(block_height_u, 0, block_height_str.size());
    memset(empty_disk_capacity_u, 0, empty_disk_capacity_str.size());
    memset(meaningful_workload_size_u, 0, meaningful_workload_size_str.size());
    memcpy(block_height_u, block_height_str.c_str(), block_height_str.size());
    memcpy(empty_disk_capacity_u, empty_disk_capacity_str.c_str(), empty_disk_capacity_str.size());
    memcpy(meaningful_workload_size_u, meaningful_workload_size_str.c_str(), meaningful_workload_size_str.size());

    size_t block_hash_len = strlen(block_hash);
    ecc_key_pair id_key_pair = id_get_key_pair();
    size_t buf_len = sizeof(id_key_pair.pub_key) + block_height_str.size() + block_hash_len / 2 + HASH_LENGTH + empty_disk_capacity_str.size() + meaningful_workload_size_str.size();
    uint8_t *sigbuf = (uint8_t *)malloc(buf_len);
    memset(sigbuf, 0, buf_len);
    uint8_t *p_sigbuf = sigbuf;

    // Convert to bytes and concat
    memcpy(sigbuf, &id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    sigbuf += sizeof(id_key_pair.pub_key);
    memcpy(sigbuf, block_height_u, block_height_str.size());
    sigbuf += block_height_str.size();
    byte_buf = hex_string_to_bytes(block_hash, block_hash_len);
    if (byte_buf == NULL)
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    memcpy(sigbuf, byte_buf, block_hash_len / 2);
    free(byte_buf);
    sigbuf += (block_hash_len / 2);
    memcpy(sigbuf, wl->empty_root_hash, HASH_LENGTH);
    sigbuf += HASH_LENGTH;
    memcpy(sigbuf, empty_disk_capacity_u, empty_disk_capacity_str.size());
    sigbuf += empty_disk_capacity_str.size();
    memcpy(sigbuf, meaningful_workload_size_u, meaningful_workload_size_str.size());

    // Sign work report
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    sgx_status = sgx_ecdsa_sign(p_sigbuf, buf_len,
            &id_key_pair.pri_key, p_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // Get work report string
    std::copy(get_workload()->report.begin(), get_workload()->report.end(), report);
    report[report_len - 1] = '\0';

cleanup:
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    free(block_height_u);
    free(empty_disk_capacity_u);
    free(meaningful_workload_size_u);
    free(p_sigbuf);

    return crust_status;
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

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

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
crust_status_t ecall_verify_iasreport(const char **IASReport, size_t len, entry_network_signature *p_ensig)
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
