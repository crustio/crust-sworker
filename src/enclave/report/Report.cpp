#include "Report.h"
#include "EJson.h"

/* used to store work report */
std::string work_report;
size_t empty_workload;
sgx_sha256_hash_t empty_root;

/**
 * @description: generate work report
 * @param report_len (out) -> report's length
 * @return: status
 */
crust_status_t generate_work_report(size_t *report_len)
{
    Workload *p_workload = Workload::get_instance();
    ecc_key_pair id_key_pair = id_get_key_pair();
    crust_status_t crust_status = CRUST_SUCCESS;

    crust_status = p_workload->generate_empty_info(&empty_root, &empty_workload);
    if (crust_status != CRUST_SUCCESS)
    {
        return crust_status;
    }
    
    // Get old hash and size
    Workload *wl = Workload::get_instance();
    json::JSON old_files_json;
    for (int i = 0; i < wl->files_json.size(); i++)
    {
        uint8_t *p_meta = NULL;
        size_t meta_len = 0;
        crust_status = persist_get((wl->files_json[i]["hash"].ToString()+"_meta").c_str(), &p_meta, &meta_len);
        if (CRUST_SUCCESS != crust_status || p_meta == NULL)
        {
            return CRUST_STORAGE_UNSEAL_FILE_FAILED;
        }
        std::string tree_meta(reinterpret_cast<char*>(p_meta), meta_len);
        json::JSON meta_json = json::JSON::Load(tree_meta);
        old_files_json[i]["hash"] = meta_json["old_hash"].ToString();
        old_files_json[i]["size"] = meta_json["size"].ToInt();
    }

    json::JSON report_json;
    report_json["pub_key"] = std::string((const char *)hexstring(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key)));
    report_json["reserved"] = empty_workload;
    report_json["files"] = old_files_json;
    work_report = report_json.dump();
    *report_len = work_report.length();

    return crust_status;
}

/**
 * @description: get validation report
 * @param report (out) -> the validation report
 * @param report_len (in) -> the length of validation report
 * @return: status
 */
crust_status_t get_work_report(char *report, size_t /*report_len*/)
{
    memcpy(report, work_report.c_str(), work_report.size());
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
        sgx_ec256_signature_t *p_signature, char *report, size_t /*report_len*/)
{
    // Judge whether block height is expired
    if (block_height <= id_get_cwr_block_height())
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }
    id_set_cwr_block_height(block_height);

    // ----- Create signature data ----- //
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status_t sgx_status;
    ecc_key_pair id_key_pair = id_get_key_pair();
    uint8_t *block_hash_u = NULL;
    std::string block_height_str = std::to_string(block_height);
    std::string reserved_str = std::to_string(empty_workload);
    std::string files = json::JSON::Load(work_report)["files"].dump();
    remove_char(files, '\\');
    remove_char(files, '\n');
    remove_char(files, ' ');
    size_t sigbuf_len = sizeof(id_key_pair.pub_key) 
        + block_height_str.size() 
        + HASH_LENGTH 
        + reserved_str.size() 
        + files.size();
    uint8_t *sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    memset(sigbuf, 0, sigbuf_len);
    uint8_t *p_sigbuf = sigbuf;
    // Public key
    memcpy(sigbuf, &id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    sigbuf += sizeof(id_key_pair.pub_key);
    // Block height
    memcpy(sigbuf, block_height_str.c_str(), block_height_str.size());
    sigbuf += block_height_str.size();
    // Block hash
    block_hash_u = hex_string_to_bytes(block_hash, HASH_LENGTH * 2);
    if (block_hash_u == NULL)
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    memcpy(sigbuf, block_hash_u, HASH_LENGTH);
    sigbuf += HASH_LENGTH;
    free(block_hash_u);
    // Reserve
    memcpy(sigbuf, reserved_str.c_str(), reserved_str.size());
    sigbuf += reserved_str.size();
    // Files
    memcpy(sigbuf, files.c_str(), files.size());

    // Sign work report
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len, &id_key_pair.pri_key, p_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // Get work report string
    memcpy(report, work_report.c_str(), work_report.size());

    // Reset meaningful data
    Workload::get_instance()->reset_meaningful_data();


cleanup:
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    free(p_sigbuf);

    return crust_status;
}
