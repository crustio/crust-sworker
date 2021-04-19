#include "IdentityTest.h"

extern sgx_thread_mutex_t g_gen_work_report;

crust_status_t id_gen_upgrade_data_test(size_t block_height)
{
    sgx_thread_mutex_lock(&g_gen_work_report);

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    json::JSON upgrade_json;
    Workload *wl = Workload::get_instance();
    sgx_ec256_signature_t sgx_sig; 
    sgx_ecc_state_handle_t ecc_state = NULL;
    std::string mr_str;
    std::string sig_str;
    std::string pubkey_data;
    std::string block_height_data;
    std::string block_hash_data;
    std::string srd_title;
    std::string files_title;
    std::string srd_root_data;
    std::string files_root_data;
    std::string sig_data;
    std::string report_height_str;
    uint8_t *p_files = NULL;
    uint8_t *p_srd = NULL;
    size_t files_size = 0;
    size_t srd_size = 0;
    uint8_t *sigbuf = NULL;
    uint8_t *p_sigbuf = NULL;
    size_t sigbuf_len = 0;
    char *report_hash = NULL;
    size_t report_height = 0;
    size_t upgrade_buffer_len = 0;
    uint8_t *upgrade_buffer = NULL;
    uint8_t *p_upgrade_buffer = NULL;
    json::JSON wl_info;
    size_t random_time = 0;

    // ----- Generate and upload work report ----- //
    // Current era has reported, wait for next slot
    if (block_height <= wl->get_report_height())
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    if (block_height - wl->get_report_height() - WORKREPORT_REPORT_INTERVAL < REPORT_SLOT)
    {
        crust_status = CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
        goto cleanup;
    }
    report_height = wl->get_report_height();
    while (block_height - report_height > REPORT_SLOT)
    {
        report_height += REPORT_SLOT;
    }
    report_hash = (char *)enc_malloc(HASH_LENGTH * 2);
    if (report_hash == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(report_hash, 0, HASH_LENGTH * 2);
    sgx_read_rand(reinterpret_cast<uint8_t *>(report_hash), HASH_LENGTH);
    memcpy(report_hash, hexstring_safe(report_hash, HASH_LENGTH).c_str(), HASH_LENGTH * 2);
    if (CRUST_SUCCESS != crust_status)
    {
        crust_status = CRUST_UPGRADE_GET_BLOCK_HASH_FAILED;
        goto cleanup;
    }
    // Send work report
    // Wait a random time:[10, 50] block time
    sgx_read_rand(reinterpret_cast<uint8_t *>(&random_time), sizeof(size_t));
    random_time = ((random_time % (UPGRADE_WAIT_BLOCK_MAX - UPGRADE_WAIT_BLOCK_MIN + 1)) + UPGRADE_WAIT_BLOCK_MIN) * BLOCK_INTERVAL;
    log_info("Upgrade: Will generate and send work reort after %ld blocks...\n", random_time / BLOCK_INTERVAL);
    if (CRUST_SUCCESS != (crust_status = gen_and_upload_work_report_test(report_hash, report_height, random_time, false, false)))
    {
        log_err("Fatal error! Send work report failed! Error code:%lx\n", crust_status);
        crust_status = CRUST_UPGRADE_GEN_WORKREPORT_FAILED;
        goto cleanup;
    }

    // ----- Generate upgrade data ----- //
    report_height_str = std::to_string(report_height);
    // Srd and files data
    crust_status = wl->serialize_srd(&p_srd, &srd_size);
    if (CRUST_SUCCESS != crust_status)
    {
        goto cleanup;
    }
    crust_status = wl->serialize_file(&p_files, &files_size);
    if (CRUST_SUCCESS != crust_status)
    {
        goto cleanup;
    }
    wl_info = wl->gen_workload_info();
    if (crust_status != CRUST_SUCCESS)
    {
        goto cleanup;
    }
    // Sign upgrade data
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }
    sigbuf_len = sizeof(sgx_ec256_public_t) 
        + report_height_str.size()
        + HASH_LENGTH * 2
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_sha256_hash_t);
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        log_err("Malloc memory failed!\n");
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
    // Pub key
    memcpy(sigbuf, &wl->get_pub_key(), sizeof(sgx_ec256_public_t));
    sigbuf += sizeof(sgx_ec256_public_t);
    // Block height
    memcpy(sigbuf, report_height_str.c_str(), report_height_str.size());
    sigbuf += report_height_str.size();
    // Block hash
    memcpy(sigbuf, report_hash, HASH_LENGTH * 2);
    sigbuf += (HASH_LENGTH * 2);
    // Srd root
    memcpy(sigbuf, wl_info[WL_SRD_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Files root
    memcpy(sigbuf, wl_info[WL_FILE_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len,
            const_cast<sgx_ec256_private_t *>(&wl->get_pri_key()), &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // ----- Get final upgrade data ----- //
    pubkey_data.append("{\"" UPGRADE_PUBLIC_KEY "\":")
        .append("\"").append(hexstring_safe(&wl->get_pub_key(), sizeof(sgx_ec256_public_t))).append("\"");
    block_height_data.append(",\"" UPGRADE_BLOCK_HEIGHT "\":").append(report_height_str);
    block_hash_data.append(",\"" UPGRADE_BLOCK_HASH "\":")
        .append("\"").append(report_hash, HASH_LENGTH * 2).append("\"");
    srd_title.append(",\"" UPGRADE_SRD "\":");
    files_title.append(",\"" UPGRADE_FILE "\":");
    srd_root_data.append(",\"" UPGRADE_SRD_ROOT "\":")
        .append("\"").append(wl_info[WL_SRD_ROOT_HASH].ToString()).append("\"");
    files_root_data.append(",\"" UPGRADE_FILE_ROOT "\":")
        .append("\"").append(wl_info[WL_FILE_ROOT_HASH].ToString()).append("\"");
    sig_data.append(",\"" UPGRADE_SIG "\":")
        .append("\"").append(hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t))).append("\"}");
    upgrade_buffer_len = pubkey_data.size()
        + block_height_data.size()
        + block_hash_data.size()
        + srd_title.size()
        + srd_size
        + files_title.size()
        + files_size
        + srd_root_data.size()
        + files_root_data.size()
        + sig_data.size();
    upgrade_buffer = (uint8_t *)enc_malloc(upgrade_buffer_len);
    if (upgrade_buffer == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(upgrade_buffer, 0, upgrade_buffer_len);
    p_upgrade_buffer = upgrade_buffer;
    // Public key
    memcpy(upgrade_buffer, pubkey_data.c_str(), pubkey_data.size());
    upgrade_buffer += pubkey_data.size();
    // BLock height
    memcpy(upgrade_buffer, block_height_data.c_str(), block_height_data.size());
    upgrade_buffer += block_height_data.size();
    // Block hash
    memcpy(upgrade_buffer, block_hash_data.c_str(), block_hash_data.size());
    upgrade_buffer += block_hash_data.size();
    // Srd
    memcpy(upgrade_buffer, srd_title.c_str(), srd_title.size());
    upgrade_buffer += srd_title.size();
    memcpy(upgrade_buffer, p_srd, srd_size);
    upgrade_buffer += srd_size;
    // Files
    memcpy(upgrade_buffer, files_title.c_str(), files_title.size());
    upgrade_buffer += files_title.size();
    memcpy(upgrade_buffer, p_files, files_size);
    upgrade_buffer += files_size;
    // Srd root
    memcpy(upgrade_buffer, srd_root_data.c_str(), srd_root_data.size());
    upgrade_buffer += srd_root_data.size();
    // Files root
    memcpy(upgrade_buffer, files_root_data.c_str(), files_root_data.size());
    upgrade_buffer += files_root_data.size();
    // Signature
    memcpy(upgrade_buffer, sig_data.c_str(), sig_data.size());
    upgrade_buffer += sig_data.size();

    // Store upgrade data
    store_large_data(p_upgrade_buffer, upgrade_buffer_len, ocall_store_upgrade_data, wl->ocall_upgrade_mutex);


cleanup:
    sgx_thread_mutex_unlock(&g_gen_work_report);

    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    if (p_sigbuf != NULL)
    {
        free(p_sigbuf);
    }

    if (p_upgrade_buffer != NULL)
    {
        free(p_upgrade_buffer);
    }

    if (report_hash != NULL)
    {
        free(report_hash);
    }

    if (CRUST_SUCCESS == crust_status)
    {
        wl->set_upgrade_status(ENC_UPGRADE_STATUS_SUCCESS);
    }

    return crust_status;
}
