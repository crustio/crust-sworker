#include "Report.h"

/* used to store work report */
std::string work_report;
size_t meaningful_workload;
size_t empty_workload;
sgx_sha256_hash_t empty_root;

/**
 * @description: generate work report
 * @param report_len (out) -> report's length
 * @return: status
 */
crust_status_t generate_work_report(size_t *report_len)
{
    Workload *wl = get_workload();
    ecc_key_pair id_key_pair = id_get_key_pair();
    crust_status_t crust_status = CRUST_SUCCESS;

    crust_status = wl->generate_empty_info(&empty_root, &empty_workload);
    if (crust_status != CRUST_SUCCESS)
    {
        return crust_status;
    }

    crust_status = wl->generate_meaningful_info(&meaningful_workload);
    if (crust_status != CRUST_SUCCESS)
    {
        return crust_status;
    }

    work_report = "{";
    work_report += "\"pub_key\":\"" + std::string((const char *)hexstring(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key))) + "\",";
    work_report += "\"empty_root\":\"" + unsigned_char_array_to_hex_string(this->empty_root_hash, HASH_LENGTH) + "\",";
    work_report += "\"empty_workload\":" + std::to_string(empty_workload) + ",";
    work_report += "\"meaningful_workload\":" + std::to_string(meaningful_workload);
    work_report += "}";

    *report_len = work_report.size() + 1;

    return crust_status;
}

/**
 * @description: get validation report
 * @param report (out) -> the validation report
 * @param report_len (in) -> the length of validation report
 * @return: status
 */
crust_status_t get_work_report(char *report, size_t report_len)
{
    std::copy(work_report.begin(), work_report.end(), report);
    report[report_len - 1] = '\0';
    return CRUST_SUCCESS;
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
crust_status_t get_signed_work_report(const char *block_hash, size_t block_height,
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
    uint8_t *byte_buf = NULL;

    // Convert number type to string
    std::string block_height_str = std::to_string(block_height);
    std::string empty_workload_str = std::to_string(empty_workload);
    std::string meaningful_workload_str = std::to_string(meaningful_workload);
    uint8_t *block_height_u = (uint8_t *)malloc(block_height_str.size());
    uint8_t *empty_workload_u = (uint8_t *)malloc(empty_workload_str.size());
    uint8_t *meaningful_workload_size_u = (uint8_t *)malloc(meaningful_workload_str.size());
    memset(block_height_u, 0, block_height_str.size());
    memset(empty_workload_u, 0, empty_workload_str.size());
    memset(meaningful_workload_u, 0, meaningful_workload_str.size());
    memcpy(block_height_u, block_height_str.c_str(), block_height_str.size());
    memcpy(empty_workload_u, empty_workload_str.c_str(), empty_workload_str.size());
    memcpy(meaningful_workload_size_u, meaningful_workload_str.c_str(), meaningful_workload_str.size());

    size_t block_hash_len = strlen(block_hash);
    ecc_key_pair id_key_pair = id_get_key_pair();
    size_t buf_len = sizeof(id_key_pair.pub_key) + block_height_str.size() + block_hash_len / 2 + HASH_LENGTH + empty_workload_str.size() + meaningful_workload_str.size();
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
    memcpy(sigbuf, empty_workload_u, empty_workload_str.size());
    sigbuf += empty_workload_str.size();
    memcpy(sigbuf, meaningful_workload_size_u, meaningful_workload_str.size());

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
    free(empty_workload_u);
    free(meaningful_workload_size_u);
    free(p_sigbuf);

    return crust_status;
}