#include "Report.h"
#include "EJson.h"

/* used to store work report */
size_t srd_workload;
sgx_sha256_hash_t srd_root;

/* Indicates whether the current work report is validated */
sgx_thread_mutex_t g_validated_mutex = SGX_THREAD_MUTEX_INITIALIZER;
int validated_proof = 0;

extern sgx_thread_mutex_t g_checked_files_mutex;
extern sgx_thread_mutex_t g_order_files_mutex;
extern ecc_key_pair id_key_pair;

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
 * */
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

    // ----- Get files info ----- //
    Workload *wl = Workload::get_instance();
    ecc_key_pair id_key_pair = id_get_key_pair();
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status;
    // Get srd info
    crust_status = wl->generate_srd_info(&srd_root, &srd_workload);
    if (crust_status != CRUST_SUCCESS)
    {
        return crust_status;
    }
    // Get old hash and size
    json::JSON old_files_json = json::Array();
    if (wl->get_report_flag())
    {
        sgx_thread_mutex_lock(&g_checked_files_mutex);
        for (uint32_t i = 0, j = 0; i < wl->checked_files.size(); i++)
        {
            if (wl->checked_files[i][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) != 0)
            {
                continue;
            }

            uint8_t *p_meta = NULL;
            size_t meta_len = 0;
            std::string hash_str = wl->checked_files[i][FILE_HASH].ToString();
            crust_status = persist_get((hash_str+"_meta").c_str(), &p_meta, &meta_len);
            if (CRUST_SUCCESS != crust_status || p_meta == NULL)
            {
                log_err("Get file:%s meta failed!\n", hash_str.c_str());
            }
            std::string tree_meta(reinterpret_cast<char*>(p_meta), meta_len);
            json::JSON meta_json = json::JSON::Load(tree_meta);
            old_files_json[j][FILE_HASH] = meta_json[FILE_OLD_HASH].ToString();
            old_files_json[j][FILE_SIZE] = meta_json[FILE_OLD_SIZE].ToInt();
            j++;
            free(p_meta);
        }
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
    }

    // ----- Create signature data ----- //
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_ec256_signature_t sgx_sig; 
    json::JSON wr_json;
    std::string wr_str;
    uint8_t *block_hash_u = NULL;
    std::string block_height_str = std::to_string(block_height);
    std::string reserved_str = std::to_string(srd_workload);
    std::string files = old_files_json.dump();
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
    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len, &id_key_pair.pri_key, &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // Store workreport
    wr_json["pub_key"] = hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    wr_json["reserved"] = srd_workload;
    wr_json["files"] = old_files_json;
    wr_json["block_height"] = block_height_str;
    wr_json["block_hash"] = std::string(block_hash, HASH_LENGTH * 2);
    wr_json["sig"] = hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t));
    wr_str = wr_json.dump();
    ocall_store_workreport(wr_str.c_str());

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
 * */
crust_status_t get_signed_order_report()
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    size_t org_data_len = 0;
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
    order_json["files"] = json::Array();
    for (size_t i = 0; i < wl->order_files.size(); i++)
    {
        order_json["files"][i][FILE_HASH] = wl->order_files[i].first;
        order_json["files"][i][FILE_SIZE] = wl->order_files[i].second;
    }
    wl->order_files.clear();
    sgx_thread_mutex_unlock(&g_order_files_mutex);

    // Prepare order data
    std::string files_str = order_json["files"].dump();
    remove_char(files_str, ' ');
    remove_char(files_str, '\n');
    remove_char(files_str, '\\');
    uint32_t random_num = 0;
    sgx_read_rand(reinterpret_cast<unsigned char *>(&random_num), sizeof(random_num));
    std::string hex_pub_key_str = hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    std::string random_str = to_string(random_num);
    // Order report data
    order_json["pub_key"] = hex_pub_key_str;
    order_json["random"] = random_num;

    // Sign order report
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }

    org_data_len = sizeof(id_key_pair.pub_key) * 2 + files_str.size() + random_str.size();
    org_data = (uint8_t*)enc_malloc(org_data_len);
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
    sgx_status = sgx_ecdsa_sign(p_org_data, (uint32_t)org_data_len,
            &id_key_pair.pri_key, &ecc_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }

    order_json["sig"] = hexstring_safe(&ecc_signature, sizeof(sgx_ec256_signature_t));

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
