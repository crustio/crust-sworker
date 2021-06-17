#include "IdentityTest.h"

extern sgx_thread_mutex_t g_gen_work_report;

crust_status_t id_gen_upgrade_data_test(size_t block_height)
{
    SafeLock sl(g_gen_work_report);
    sl.lock();

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    Workload *wl = Workload::get_instance();

    // ----- Generate and upload work report ----- //
    // Current era has reported, wait for next slot
    if (block_height <= wl->get_report_height())
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }
    if (block_height - wl->get_report_height() < REPORT_SLOT)
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }
    size_t report_height = wl->get_report_height();
    while (block_height - report_height > REPORT_SLOT)
    {
        report_height += REPORT_SLOT;
    }
    char report_hash[HASH_LENGTH * 2];
    if (report_hash == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(report_hash, 0, HASH_LENGTH * 2);
    ocall_get_block_hash(&crust_status, report_height, report_hash, HASH_LENGTH * 2);
    if (CRUST_SUCCESS != crust_status)
    {
        return CRUST_UPGRADE_GET_BLOCK_HASH_FAILED;
    }
    // Send work report
    // Wait a random time:[10, 50] block time
    size_t random_time = 0;
    sgx_read_rand(reinterpret_cast<uint8_t *>(&random_time), sizeof(size_t));
    random_time = ((random_time % (UPGRADE_WAIT_BLOCK_MAX - UPGRADE_WAIT_BLOCK_MIN + 1)) + UPGRADE_WAIT_BLOCK_MIN) * BLOCK_INTERVAL;
    log_info("Upgrade: Will generate and send work report after %ld blocks...\n", random_time / BLOCK_INTERVAL);
    if (CRUST_SUCCESS != (crust_status = gen_and_upload_work_report_test(report_hash, report_height, random_time, false, false)))
    {
        log_err("Fatal error! Send work report failed! Error code:%lx\n", crust_status);
        return CRUST_UPGRADE_GEN_WORKREPORT_FAILED;
    }
    log_debug("Upgrade: generate and send work report successfully!\n");

    // ----- Generate upgrade data ----- //
    // Clean pending status file
    wl->clean_pending_file();
    // Sign upgrade data
    std::string report_height_str = std::to_string(report_height);
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    Defer defer_ecc_state([&ecc_state](void) {
        if (ecc_state != NULL)
        {
            sgx_ecc256_close_context(ecc_state);
        }
    });
    uint8_t *p_srd_root = NULL;
    std::vector<uint8_t> srd_data = wl->serialize_srd(&crust_status, &p_srd_root);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    log_debug("Serialize srd data successfully!\n");
    uint8_t *p_file_root = NULL;
    std::vector<uint8_t> file_data = wl->serialize_file(&crust_status, &p_file_root);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    log_debug("Serialize file data successfully!\n");
    std::vector<uint8_t> sig_buffer;
    // Pub key
    const uint8_t *p_pub_key = reinterpret_cast<const uint8_t *>(&wl->get_pub_key());
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_pub_key, sizeof(sgx_ec256_public_t))))
    {
        return crust_status;
    }
    // Block height
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, report_height_str)))
    {
        return crust_status;
    }
    // Block hash
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, reinterpret_cast<uint8_t *>(report_hash), HASH_LENGTH * 2)))
    {
        return crust_status;
    }
    // Srd root
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_srd_root, HASH_LENGTH)))
    {
        return crust_status;
    }
    // Files root
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_file_root, HASH_LENGTH)))
    {
        return crust_status;
    }
    sgx_ec256_signature_t sgx_sig; 
    sgx_status = sgx_ecdsa_sign(sig_buffer.data(), sig_buffer.size(),
            const_cast<sgx_ec256_private_t *>(&wl->get_pri_key()), &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    log_debug("Generate upgrade signature successfully!\n");

    // ----- Get final upgrade data ----- //
    std::vector<uint8_t> upgrade_buffer;
    // Public key
    std::string pubkey_data = "{\"" UPGRADE_PUBLIC_KEY "\":\"" + hexstring_safe(&wl->get_pub_key(), sizeof(sgx_ec256_public_t)) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, pubkey_data)))
    {
        return crust_status;
    }
    // BLock height
    std::string block_height_data = ",\"" UPGRADE_BLOCK_HEIGHT "\":" + report_height_str;
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, block_height_data)))
    {
        return crust_status;
    }
    // Block hash
    std::string block_hash_data = std::string(",\"" UPGRADE_BLOCK_HASH "\":") + "\"" + std::string(report_hash, HASH_LENGTH * 2) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, block_hash_data)))
    {
        return crust_status;
    }
    // Srd
    do
    {
        std::string srd_title(",\"" UPGRADE_SRD "\":");
        if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, srd_title)))
        {
            return crust_status;
        }
        if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, srd_data.data(), srd_data.size())))
        {
            return crust_status;
        }
    } while (0);
    // Files
    do
    {
        std::string files_title(",\"" UPGRADE_FILE "\":");
        if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, files_title)))
        {
            return crust_status;
        }
        if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, file_data.data(), file_data.size())))
        {
            return crust_status;
        }
    } while (0);
    // Srd root
    std::string srd_root_data = ",\"" UPGRADE_SRD_ROOT "\":\"" + hexstring_safe(p_srd_root, HASH_LENGTH) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, srd_root_data)))
    {
        return crust_status;
    }
    // Files root
    std::string files_root_data = ",\"" UPGRADE_FILE_ROOT "\":\"" + hexstring_safe(p_file_root, HASH_LENGTH) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, files_root_data)))
    {
        return crust_status;
    }
    // Signature
    std::string sig_data = ",\"" UPGRADE_SIG "\":\"" + hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t)) + "\"}";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, sig_data)))
    {
        return crust_status;
    }

    // Store upgrade data
    store_large_data(upgrade_buffer.data(), upgrade_buffer.size(), ocall_store_upgrade_data, wl->ocall_upgrade_mutex);
    log_debug("Store upgrade data successfully!\n");

    wl->set_upgrade_status(ENC_UPGRADE_STATUS_SUCCESS);

    return crust_status;
}
