#include "Report.h"
#include "EJson.h"


/* Indicates whether the current work report is validated */
sgx_thread_mutex_t g_validated_mutex = SGX_THREAD_MUTEX_INITIALIZER;
int validated_proof = 0;

extern sgx_thread_mutex_t g_srd_mutex;
extern sgx_thread_mutex_t g_checked_files_mutex;
extern sgx_thread_mutex_t g_order_files_mutex;

/**
 * @description: add validated proof
 */
void report_add_validated_proof()
{
    sgx_thread_mutex_lock(&g_validated_mutex);
    if (validated_proof >= 2)
    {
        validated_proof = 2;
    }
    else
    {
        validated_proof++;
    }
    sgx_thread_mutex_unlock(&g_validated_mutex);
}

/**
 * @description: reduce validated proof
 */
void report_reduce_validated_proof()
{
    sgx_thread_mutex_lock(&g_validated_mutex);
    if (validated_proof <= 0)
    {
        validated_proof = 0;
    }
    else
    {
        validated_proof--;
    }
    sgx_thread_mutex_unlock(&g_validated_mutex);
}

/**
 * @description: Has validated proof
 * @return: true or false
 */
bool report_has_validated_proof() {
    return validated_proof > 0;
}

/**
 * @description: Get signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @return: sign status
 */
crust_status_t get_signed_work_report(const char *block_hash, size_t block_height)
{
    // Judge whether the current data is validated 
    if (!report_has_validated_proof())
    {
        return CRUST_WORK_REPORT_NOT_VALIDATED;
    }

    // Judge whether block height is expired
    if (block_height == 0 || (block_height - 1)/ERA_LENGTH < id_get_report_slot())
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }
    id_set_report_slot((block_height - 1)/ERA_LENGTH + 1);

    // The first report after restart will not be processed
    if (id_just_after_restart())
    {
        id_set_just_after_restart(false);
        return CRUST_FIRST_WORK_REPORT_AFTER_REPORT;
    }

    Workload *wl = Workload::get_instance();
    ecc_key_pair id_key_pair = id_get_key_pair();
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status;
    // ----- Get srd info ----- //
    sgx_thread_mutex_lock(&g_srd_mutex);
    size_t srd_workload;
    sgx_sha256_hash_t srd_root;
    // Get hashs for hashing
    size_t g_hashs_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        g_hashs_num += it.second.size();
    }
    uint8_t *hashs = (uint8_t *)enc_malloc(g_hashs_num * HASH_LENGTH);
    if (hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    size_t hashs_len = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        for (auto g_hash : it.second)
        {
            memcpy(hashs + hashs_len, g_hash, HASH_LENGTH);
            hashs_len += HASH_LENGTH;
        }
    }
    // Generate srd information
    if (hashs_len == 0)
    {
        srd_workload = 0;
        memset(srd_root, 0, HASH_LENGTH);
    }
    else
    {
        srd_workload = (hashs_len / HASH_LENGTH) * 1024 * 1024 * 1024;
        sgx_sha256_msg(hashs, (uint32_t)hashs_len, &srd_root);
    }
    free(hashs);
    sgx_thread_mutex_unlock(&g_srd_mutex);
    
    // ----- Get files info ----- //
    std::string old_files = "[";
    if (wl->get_report_flag())
    {
        sgx_thread_mutex_lock(&g_checked_files_mutex);
        for (uint32_t i = 0; i < wl->checked_files.size(); i++)
        {
            if (wl->checked_files[i][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) != 0)
            {
                continue;
            }

            old_files.append("{\"").append(FILE_HASH).append("\":")
                .append("\"").append(wl->checked_files[i][FILE_OLD_HASH].ToString()).append("\",");
            old_files.append("\"").append(FILE_SIZE).append("\":")
                .append(std::to_string(wl->checked_files[i][FILE_OLD_SIZE].ToInt())).append("}");
            if (i != wl->checked_files.size() - 1)
            {
                old_files.append(",");
            }
        }
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
    }
    old_files.append("]");

    // ----- Create signature data ----- //
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_ec256_signature_t sgx_sig; 
    std::string wr_str;
    uint8_t *block_hash_u = NULL;
    std::string block_height_str = std::to_string(block_height);
    std::string reserved_str = std::to_string(srd_workload);
    size_t sigbuf_len = sizeof(id_key_pair.pub_key) 
        + block_height_str.size() 
        + HASH_LENGTH 
        + reserved_str.size() 
        + old_files.size();
    uint8_t *sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
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
    memcpy(sigbuf, old_files.c_str(), old_files.size());

    // Sign work report
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }
    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len, &id_key_pair.pri_key, &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // Store workreport
    wr_str.append("{");
    wr_str.append("\"").append(WORKREPORT_PUB_KEY).append("\":")
        .append("\"").append(hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key))).append("\",");
    wr_str.append("\"").append(WORKREPORT_BLOCK_HEIGHT).append("\":")
        .append("\"").append(block_height_str).append("\",");
    wr_str.append("\"").append(WORKREPORT_BLOCK_HASH).append("\":")
        .append("\"").append(block_hash, HASH_LENGTH * 2).append("\",");
    wr_str.append("\"").append(WORKREPORT_RESERVED).append("\":")
        .append(std::to_string(srd_workload)).append(",");
    wr_str.append("\"").append(WORKREPORT_FILES).append("\":")
        .append(old_files).append(",");
    wr_str.append("\"").append(WORKREPORT_SIG).append("\":")
        .append("\"").append(hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t))).append("\"");
    wr_str.append("}");
    store_large_data(wr_str, ocall_store_workreport, wl->ocall_wr_mutex);

    // Reset meaningful data
    wl->set_report_flag(true);


cleanup:
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    free(p_sigbuf);

    report_reduce_validated_proof();
    id_set_just_after_restart(false);
    return crust_status;
}

/**
 * @description: Get signed order report
 * @return: Get status
 */
crust_status_t get_signed_order_report()
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    uint32_t org_data_len = 0;
    uint8_t *org_data = NULL;
    uint8_t *p_org_data = NULL;
    std::string order_str;
    sgx_ec256_signature_t ecc_signature;
    sgx_ecc_state_handle_t ecc_state = NULL;

    // Get order files
    sgx_thread_mutex_lock(&g_order_files_mutex);
    Workload *wl = Workload::get_instance();
    if (wl->order_files.size() == 0)
    {
        sgx_thread_mutex_unlock(&g_order_files_mutex);
        return CRUST_REPORT_NO_ORDER_FILE;
    }
    json::JSON order_json;
    order_json[ORDERREPORT_FILES] = json::Array();
    for (size_t i = 0; i < wl->order_files.size(); i++)
    {
        order_json[ORDERREPORT_FILES][i][FILE_HASH] = wl->order_files[i].first;
        order_json[ORDERREPORT_FILES][i][FILE_SIZE] = wl->order_files[i].second;
    }
    wl->order_files.clear();
    sgx_thread_mutex_unlock(&g_order_files_mutex);

    // Prepare order data
    ecc_key_pair id_key_pair = id_get_key_pair();
    std::string files_str = order_json[ORDERREPORT_FILES].dump();
    remove_char(files_str, ' ');
    remove_char(files_str, '\n');
    remove_char(files_str, '\\');
    uint32_t random_num = 0;
    sgx_read_rand(reinterpret_cast<unsigned char *>(&random_num), sizeof(random_num));
    std::string hex_pub_key_str = hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    std::string random_str = to_string(random_num);
    // Order report data
    order_json[ORDERREPORT_PUB_KEY] = hex_pub_key_str;
    order_json[ORDERREPORT_RANDOM] = random_num;

    // Sign order report
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }

    org_data_len = sizeof(id_key_pair.pub_key) * 2 + files_str.size() + random_str.size();
    org_data = (uint8_t*)enc_malloc(org_data_len);
    if (org_data == NULL)
    {
        log_err("Malloc memory failed!\n");
        goto cleanup;
    }
    memset(org_data, 0, org_data_len);
    p_org_data = org_data;
    // Copy pubkey
    memcpy(org_data, hex_pub_key_str.c_str(), sizeof(id_key_pair.pub_key) * 2);
    org_data += sizeof(id_key_pair.pub_key) * 2;
    // Copy files
    memcpy(org_data, files_str.c_str(), files_str.size());
    org_data += files_str.size();
    // Copy random
    memcpy(org_data, random_str.c_str(), random_str.size());
    sgx_status = sgx_ecdsa_sign(p_org_data, org_data_len,
            &id_key_pair.pri_key, &ecc_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }

    order_json[ORDERREPORT_SIG] = hexstring_safe(&ecc_signature, sizeof(sgx_ec256_signature_t));

    order_str = order_json.dump();
    remove_char(order_str, ' ');
    remove_char(order_str, '\n');
    remove_char(order_str, '\\');
    ocall_store_order_report(order_str.c_str(), order_str.size());


cleanup:

    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    free(p_org_data);

    return crust_status;
}
