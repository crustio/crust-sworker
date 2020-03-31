#include "Enclave.h"

using namespace std;

// TODO: Divide ecall into different files according to functions
/* Used to store validation status */
enum ValidationStatus validation_status = ValidateStop;
extern attest_status_t g_att_status;
extern ecc_key_pair id_key_pair;
extern uint8_t off_chain_pub_key[];
string g_run_mode = APP_RUN_MODE_SINGLE;
size_t now_work_report_block_height = 0;

/**
 * @description: ecall main loop
 * @param empty_path -> the empty directory path
 */
void ecall_main_loop(const char *empty_path, const char *recover_file_path)
{
    while (true)
    {
        cfeprintf("-----Meaningful Validation-----\n");
        /* Meaningful */
        validation_status = ValidateMeaningful;
        common_status_t common_status = CRUST_SUCCESS;
        ipc_status_t ipc_status = IPC_SUCCESS;
        Node *diff_files = NULL;
        ocall_get_diff_files(&diff_files);
        size_t diff_files_num = 0;
        ocall_get_diff_files_num(&diff_files_num);
        validate_meaningful_disk(diff_files, diff_files_num);

        cfeprintf("-----Empty Validation-----\n");
        /* Empty */
        validation_status = ValidateEmpty;
        ecall_generate_empty_root();
        validate_empty_disk(empty_path);
        ecall_generate_empty_root();

        cfeprintf("-----Validation Waiting-----\n");
        /* Show result */
        validation_status = ValidateWaiting;
        get_workload()->show();

        /* Do workload attestation */
        if (g_run_mode.compare(APP_RUN_MODE_MULTIPLE) == 0)
        {
            if (IPC_SUCCESS != (ipc_status = ecall_attest_session_starter(ATTEST_DATATYPE_WORKLOAD)))
            {
                cfeprintf("Send workload to monitor failed!Error code:%lx\n", ipc_status);
            }
            else
            {
                cfeprintf("Send workload to monitor successfully!\n");
            }
        }
        else if (g_run_mode.compare(APP_RUN_MODE_SINGLE) == 0)
        {
            if (CRUST_SUCCESS != (common_status = ecall_store_enclave_data(recover_file_path)))
            {
                cfeprintf("Store enclave data failed!Error code:%lx\n", common_status);
            }
            else
            {
                cfeprintf("Store enclave data successfully!\n");
            }
        }
        else
        {
            cfeprintf("Wrong TEE run mode!\n");
        }

        ocall_usleep(MAIN_LOOP_WAIT_TIME);
    }
}

/**
 * @description: Store enclave data to file
 * @return: Store status
 * */
common_status_t ecall_store_enclave_data(const char *recover_file_path)
{
    // TODO: Group seal related functions into a class
    std::string seal_data = get_workload()->serialize_workload();
    seal_data.append(CRUST_SEPARATOR)
        .append(hexstring(&id_key_pair, sizeof(id_key_pair)));
    seal_data.append(CRUST_SEPARATOR)
        .append(std::to_string(now_work_report_block_height));
    seal_data.append(CRUST_SEPARATOR)
        .append(g_crust_account_id);
    // Seal workload string
    sgx_status_t sgx_status = SGX_SUCCESS;
    common_status_t common_status = CRUST_SUCCESS;
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, seal_data.size());
    sgx_sealed_data_t *p_sealed_data = (sgx_sealed_data_t *)malloc(sealed_data_size);
    memset(p_sealed_data, 0, sealed_data_size);
    sgx_attributes_t sgx_attr;
    sgx_attr.flags = 0xFF0000000000000B;
    sgx_attr.xfrm = 0;
    sgx_misc_select_t sgx_misc = 0xF0000000;
    sgx_status = sgx_seal_data_ex(0x0001, sgx_attr, sgx_misc,
            0, NULL, seal_data.size(), (const uint8_t*)seal_data.c_str(),
            sealed_data_size, p_sealed_data);
    if (SGX_SUCCESS != sgx_status)
    {
        common_status = CRUST_SEAL_DATA_FAILED;
        goto cleanup;
    }

    // Store sealed data to file
    if (SGX_SUCCESS != ocall_save_file(recover_file_path, (unsigned char *)p_sealed_data, sealed_data_size))
    {
        common_status = CRUST_STORE_DATA_TO_FILE_FAILED;
    }

cleanup:
    free(p_sealed_data);

    return common_status;
}

/**
 * @description: Restore enclave data from file
 * @return: Restore status
 * */
common_status_t ecall_restore_enclave_data(const char * recover_file_path)
{
    unsigned char *p_sealed_data = NULL;
    common_status_t common_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    size_t spos = 0, epos = 0;
    size_t sealed_data_size;
    string unseal_data;
    string plot_data;
    string id_key_pair_str;
    uint8_t *byte_buf = NULL;

    /* Unseal data */
    // Get sealed data from file
    if (SGX_SUCCESS != ocall_get_file(recover_file_path, &p_sealed_data, &sealed_data_size))
    {
        common_status = CRUST_GET_DATA_FROM_FILE_FAILED;
        return common_status;
    }
    // Create buffer in enclave
    sgx_sealed_data_t *p_sealed_data_r = (sgx_sealed_data_t *)malloc(sealed_data_size);
    memset(p_sealed_data_r, 0, sealed_data_size);
    memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
    // Create buffer for decrypted data
    uint32_t decrypted_data_len = sgx_get_encrypt_txt_len(p_sealed_data_r);
    uint8_t *p_decrypted_data = (uint8_t *)malloc(decrypted_data_len);
    // Unseal sealed data
    sgx_status = sgx_unseal_data(p_sealed_data_r, NULL, NULL,
            p_decrypted_data, &decrypted_data_len);
    if (SGX_SUCCESS != sgx_status)
    {
        common_status = CRUST_UNSEAL_DATA_FAILED;
        goto cleanup;
    }

    /* Restore related data */
    unseal_data = std::string((const char *)p_decrypted_data, decrypted_data_len);
    // Get plot data
    spos = 0;
    epos = unseal_data.find(CRUST_SEPARATOR, spos);
    plot_data = unseal_data.substr(spos, epos - spos);
    if (CRUST_SUCCESS != (common_status = get_workload()->restore_workload(plot_data)))
    {
        common_status = CRUST_BAD_SEAL_DATA;
        goto cleanup;
    }
    // Get id_key_pair
    spos = epos + strlen(CRUST_SEPARATOR);
    epos = unseal_data.find(CRUST_SEPARATOR, spos);
    if (epos == std::string::npos)
    {
        common_status = CRUST_BAD_SEAL_DATA;
        goto cleanup;
    }
    id_key_pair_str = unseal_data.substr(spos, epos - spos);
    memset(&id_key_pair, 0, sizeof(id_key_pair));
    byte_buf = hex_string_to_bytes(id_key_pair_str.c_str(), id_key_pair_str.size());
    if (byte_buf == NULL)
    {
        common_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    memcpy(&id_key_pair, byte_buf, sizeof(id_key_pair));
    free(byte_buf);
    // Get now_work_report_block_height
    spos = epos + strlen(CRUST_SEPARATOR);
    epos = unseal_data.find(CRUST_SEPARATOR, spos);
    if (epos == std::string::npos)
    {
        common_status = CRUST_BAD_SEAL_DATA;
        goto cleanup;
    }
    std::stringstream now_work_report_block_height_stream(unseal_data.substr(spos, epos - spos));
    now_work_report_block_height_stream >> now_work_report_block_height;

    // Get g_crust_account_id
    spos = epos + strlen(CRUST_SEPARATOR);
    epos = unseal_data.size();
    g_crust_account_id = unseal_data.substr(spos, epos - spos);

cleanup:
    free(p_sealed_data_r);
    free(p_decrypted_data);

    return common_status;
}

common_status_t ecall_cmp_crust_account_id(const char *account_id, size_t len)
{
    string account_id_str = string(account_id, len);
    if (g_crust_account_id.compare(account_id_str) != 0)
    {
        return CRUST_NOT_EQUAL;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Set crust account id
 * @return: Set status
 * */
common_status_t ecall_set_crust_account_id(const char *account_id, size_t len)
{
    // Check if value has been set
    if (g_is_set_account_id)
    {
        return CRUST_DOUBLE_SET_VALUE;
    }

    char *buffer = (char *)malloc(len);
    if (buffer == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(buffer, 0, len);
    memcpy(buffer, account_id, len);
    g_crust_account_id = string(buffer, len);
    g_is_set_account_id = true;

    return CRUST_SUCCESS;
}

/**
 * @description: Set application run mode
 * */
void ecall_set_run_mode(const char *mode, size_t len)
{
    g_run_mode = std::string(mode, len);
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
 * @param block_hash -> used to generate validation report
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
validate_status_t ecall_get_signed_validation_report(const char *block_hash, size_t block_height,
                                                     sgx_ec256_signature_t *p_signature,
                                                     char *report, size_t report_len)
{
    /* Create signature data */
    validate_status_t validate_status = VALIDATION_SUCCESS;
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
        validate_status = VALIDATION_UNEXPECTED_ERROR;
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

    /* Sign work report */
	sgx_status = sgx_ecc256_open_context(&ecc_state);
	if (SGX_SUCCESS != sgx_status)
	{
        validate_status = VALIDATION_REPORT_SIGN_FAILED;
        goto cleanup;
	}

	sgx_status = sgx_ecdsa_sign(p_sigbuf, buf_len,
            &id_key_pair.pri_key, p_signature, ecc_state);
	if (SGX_SUCCESS != sgx_status)
	{
        validate_status = VALIDATION_REPORT_SIGN_FAILED;
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

    return validate_status;
}

common_status_t ecall_sign_network_entry(const char *p_partial_data, uint32_t data_size,
                                         sgx_ec256_signature_t *p_signature)
{
    std::string data_str(p_partial_data, data_size);
    data_str.append(g_crust_account_id);
    sgx_status_t sgx_status = SGX_SUCCESS;
    common_status_t common_status = CRUST_SUCCESS;
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_FAILED;
    }

    sgx_status = sgx_ecdsa_sign((const uint8_t*)data_str.c_str(), data_str.size(),
            &id_key_pair.pri_key, p_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        common_status = CRUST_SGX_SIGN_FAILED;
    }

    sgx_ecc256_close_context(ecc_state);

    return common_status;
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
    // Generate public and private key
    sgx_ec256_public_t pub_key;
    sgx_ec256_private_t pri_key;
    memset(&pub_key, 0, sizeof(pub_key));
    memset(&pri_key, 0, sizeof(pri_key));
    sgx_status_t se_ret;
    sgx_ecc_state_handle_t ecc_state = NULL;
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }
    se_ret = sgx_ecc256_create_key_pair(&pri_key, &pub_key, ecc_state);
    if (SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    // Store key pair in enclave
    memset(&id_key_pair.pub_key, 0, sizeof(id_key_pair.pub_key));
    memset(&id_key_pair.pri_key, 0, sizeof(id_key_pair.pri_key));
    memcpy(&id_key_pair.pub_key, &pub_key, sizeof(pub_key));
    memcpy(&id_key_pair.pri_key, &pri_key, sizeof(pri_key));

    return SGX_SUCCESS;
}

/**
 * @description: get sgx report, our generated public key contained
 *  in report data
 * @return: get sgx report status
 * */
sgx_status_t ecall_get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{

    // Copy public key to report data
    sgx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    memcpy(&report_data, &id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
#ifdef SGX_HW_SIM
    return sgx_create_report(NULL, &report_data, report);
#else
    return sgx_create_report(target_info, &report_data, report);
#endif
}

/**
 * @description: generate current code measurement
 * @return: generate status
 * */
sgx_status_t ecall_gen_sgx_measurement()
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_report_t verify_report;
    sgx_target_info_t verify_target_info;
    sgx_report_data_t verify_report_data;

    memset(&verify_report, 0, sizeof(sgx_report_t));
    memset(&verify_report_data, 0, sizeof(sgx_report_data_t));
    memset(&verify_target_info, 0, sizeof(sgx_target_info_t));

    status = sgx_create_report(&verify_target_info, &verify_report_data, &verify_report);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    memset(&current_mr_enclave, 0, sizeof(sgx_measurement_t));
    memcpy(&current_mr_enclave, &verify_report.body.mr_enclave, sizeof(sgx_measurement_t));

    return status;
}

/**
 * @description: Store off-chain node quote and verify signature
 * @return: Store status
 * */
common_status_t ecall_store_quote(const char *quote, size_t len,
                                  const uint8_t *p_data, uint32_t data_size, sgx_ec256_signature_t *p_signature)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    common_status_t common_status = CRUST_SUCCESS;
    uint8_t result;
    sgx_quote_t *offChain_quote = (sgx_quote_t *)malloc(len);
    if (off_chain_pub_key == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }

    memset(offChain_quote, 0, len);
    memcpy(offChain_quote, quote, len);
    unsigned char *p_report_data = offChain_quote->report_body.report_data.d;
    memcpy(off_chain_pub_key, p_report_data, REPORT_DATA_SIZE);

    // Verify off chain node's identity
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_FAILED;
    }

    sgx_status = sgx_ecdsa_verify(p_data, data_size,
            (sgx_ec256_public_t*)off_chain_pub_key,
            p_signature, &result, ecc_state);
    if (SGX_SUCCESS != sgx_status || SGX_EC_VALID != result)
    {
        common_status = CRUST_SGX_VERIFY_SIG_FAILED;
    }

    sgx_ecc256_close_context(ecc_state);

    return common_status;
}

/**
 * @description: verify IAS report
 * @return: verify status
 * */
ias_status_t ecall_verify_iasreport(const char **IASReport, size_t len, entry_network_signature *p_ensig)
{
    return ecall_verify_iasreport_real(IASReport, len, p_ensig);
}
