#include "ReportTest.h"


std::string g_work_report_test;

extern sgx_thread_mutex_t g_gen_work_report;

/**
 * @description: Get generated work report
 * @return: Generated work report
 */
std::string get_generated_work_report_test()
{
    return g_work_report_test;
}

/**
 * @description: Get generated work report
 * @return: Generated work report
 */

/**
 * @description: Generate and upload signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @param wait_time -> Waiting time before upload
 * @param is_upgrading -> Is this upload kind of upgrade
 * @param locked -> Lock this upload or not
 * @return: sign status
 */
crust_status_t gen_and_upload_work_report_test(const char *block_hash, size_t block_height, long /*wait_time*/, bool is_upgrading, bool locked /*=true*/)
{
    SafeLock gen_sl(g_gen_work_report);
    if (locked)
    {
        gen_sl.lock();
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    // Wait indicated time

    // Generate work report
    if (CRUST_SUCCESS != (crust_status = gen_work_report_test(block_hash, block_height, is_upgrading)))
    {
        return crust_status;
    }

    // Upload work report
    ocall_upload_workreport_test(&crust_status, g_work_report_test.c_str());

    // Confirm work report result

    return crust_status;
}

/**
 * @description: Get signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @param is_upgrading -> Check if this turn is uprade
 * @return: sign status
 */
crust_status_t gen_work_report_test(const char *block_hash, size_t block_height, bool is_upgrading)
{
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    // Judge whether block height is expired
    if (block_height == 0 || block_height - wl->get_report_height() < REPORT_SLOT)
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }

    Defer defer_status([wl, &block_height](void) {
        wl->set_report_height(block_height);
        wl->reduce_restart_flag();
        wl->set_report_file_flag(true);
        wl->report_reset_validated_proof();
    });

    if (wl->get_restart_flag())
    {
        // The first 4 report after restart will not be processed
        return CRUST_FIRST_WORK_REPORT_AFTER_REPORT;
    }
    if (!wl->get_report_file_flag())
    {
        // Have files and no karst
        return CRUST_SERVICE_UNAVAILABLE;
    }

    ecc_key_pair id_key_pair = wl->get_key_pair();
    sgx_status_t sgx_status;
    // Lock variable

    // ----- Get srd info ----- //
    SafeLock srd_sl(wl->srd_mutex);
    srd_sl.lock();
    // Compute srd root hash
    size_t srd_workload;
    sgx_sha256_hash_t srd_root;
    size_t g_hashs_num = wl->srd_hashs.size();
    if (g_hashs_num > 0)
    {
        uint8_t *hashs = (uint8_t *)enc_malloc(g_hashs_num * HASH_LENGTH);
        if (hashs == NULL)
        {
            log_err("Malloc memory failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        size_t hashs_offset = 0;
        for (auto g_hash : wl->srd_hashs)
        {
            memcpy(hashs + hashs_offset, g_hash, HASH_LENGTH);
            hashs_offset += HASH_LENGTH;
        }
        // Generate srd information
        srd_workload = g_hashs_num * 1024 * 1024 * 1024;
        sgx_sha256_msg(hashs, (uint32_t)(g_hashs_num * HASH_LENGTH), &srd_root);
        free(hashs);
    }
    else
    {
        srd_workload = 0;
        memset(srd_root, 0, HASH_LENGTH);
    }
    srd_sl.unlock();

    // ----- Get files info ----- //
    SafeLock sealed_files_sl(wl->file_mutex);
    sealed_files_sl.lock();
    // Clear reported_files_idx
    wl->reported_files_idx.clear();
    std::string added_files = "[";
    std::string deleted_files = "[";
    size_t reported_files_acc = 0;
    long long files_size = 0;
    std::vector<size_t> report_valid_idx_v;
    for (uint32_t i = 0; i < wl->sealed_files.size(); i++)
    {
        // Get report information
        auto status = &wl->sealed_files[i][FILE_STATUS];
        if (is_upgrading)
        {
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID 
                    && status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID)
            {
                report_valid_idx_v.push_back(i);
                files_size += wl->sealed_files[i][FILE_SIZE].ToInt();
            }
        }
        else
        {
            // Write current status to waiting status
            status->set_char(WAITING_STATUS, status->get_char(CURRENT_STATUS));
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                report_valid_idx_v.push_back(i);
            }
            if (status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID)
            {
                files_size += wl->sealed_files[i][FILE_SIZE].ToInt();
            }
            // Generate report files queue
            if (reported_files_acc < WORKREPORT_FILE_LIMIT)
            {
                if ((status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID && status->get_char(ORIGIN_STATUS) == FILE_STATUS_UNVERIFIED)
                        || (status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED && status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID))
                {
                    std::string file_str;
                    file_str.append("{\"").append(FILE_CID).append("\":")
                        .append("\"").append(wl->sealed_files[i][FILE_CID].ToString()).append("\",");
                    file_str.append("\"").append(FILE_SIZE).append("\":")
                        .append(std::to_string(wl->sealed_files[i][FILE_SIZE].ToInt())).append(",");
                    file_str.append("\"").append(FILE_CHAIN_BLOCK_NUM).append("\":")
                        .append(std::to_string(wl->sealed_files[i][FILE_CHAIN_BLOCK_NUM].ToInt())).append("}");
                    if (status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
                    {
                        if (deleted_files.size() != 1)
                        {
                            deleted_files.append(",");
                        }
                        deleted_files.append(file_str);
                        // Update new files size
                        files_size -= wl->sealed_files[i][FILE_SIZE].ToInt();
                    }
                    else if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                    {
                        if (added_files.size() != 1)
                        {
                            added_files.append(",");
                        }
                        added_files.append(file_str);
                        // Update new files size
                        files_size += wl->sealed_files[i][FILE_SIZE].ToInt();
                    }
                    wl->reported_files_idx.insert(wl->sealed_files[i][FILE_CID].ToString());
                    reported_files_acc++;
                }
            }
        }
    }
    added_files.append("]");
    deleted_files.append("]");
    // Generate files information
    size_t files_root_buffer_len = report_valid_idx_v.size() * HASH_LENGTH;
    sgx_sha256_hash_t files_root;
    uint8_t *files_root_buffer = NULL;
    if (files_root_buffer_len > 0)
    {
        files_root_buffer = (uint8_t *)enc_malloc(files_root_buffer_len);
        if (files_root_buffer == NULL)
        {
            return CRUST_MALLOC_FAILED;
        }
        memset(files_root_buffer, 0, files_root_buffer_len);
        for (size_t i = 0; i < report_valid_idx_v.size(); i++)
        {
            size_t idx = report_valid_idx_v[i];
            std::string file_id;
            file_id.append(wl->sealed_files[idx][FILE_CID].ToString())
                .append(std::to_string(wl->sealed_files[idx][FILE_SIZE].ToInt()));
            sgx_sha256_hash_t file_id_hash;
            sgx_sha256_msg(reinterpret_cast<const uint8_t *>(file_id.c_str()), file_id.size(), &file_id_hash);
            memcpy(files_root_buffer + i * HASH_LENGTH, reinterpret_cast<uint8_t *>(&file_id_hash), HASH_LENGTH);
        }
        sgx_sha256_msg(files_root_buffer, files_root_buffer_len, &files_root);
        free(files_root_buffer);
    }
    else
    {
        memset(&files_root, 0, sizeof(sgx_sha256_hash_t));
    }
    sealed_files_sl.unlock();
    
    // ----- Create signature data ----- //
    std::string pre_pub_key;
    size_t pre_pub_key_size = 0;
    if (wl->is_upgrade())
    {
        pre_pub_key_size = sizeof(wl->pre_pub_key);
        pre_pub_key = hexstring_safe(&wl->pre_pub_key, sizeof(wl->pre_pub_key));
    }
    std::string block_height_str = std::to_string(block_height);
    std::string reserved_str = std::to_string(srd_workload);
    std::string files_size_str = std::to_string(files_size);
    size_t sigbuf_len = sizeof(id_key_pair.pub_key) 
        + pre_pub_key_size
        + block_height_str.size()
        + HASH_LENGTH
        + reserved_str.size()
        + files_size_str.size()
        + sizeof(sgx_sha256_hash_t)
        + sizeof(sgx_sha256_hash_t)
        + added_files.size()
        + deleted_files.size();
    uint8_t *sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(sigbuf, 0, sigbuf_len);
    uint8_t *p_sigbuf = sigbuf;
    Defer defer_sigbuf([p_sigbuf](void) {
        if (p_sigbuf != NULL)
        {
            free(p_sigbuf);
        }
    });
    // Current public key
    memcpy(sigbuf, &id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    sigbuf += sizeof(id_key_pair.pub_key);
    // Previous public key
    if (wl->is_upgrade())
    {
        memcpy(sigbuf, &wl->pre_pub_key, pre_pub_key_size);
        sigbuf += pre_pub_key_size;
    }
    // Block height
    memcpy(sigbuf, block_height_str.c_str(), block_height_str.size());
    sigbuf += block_height_str.size();
    // Block hash
    uint8_t *block_hash_u = hex_string_to_bytes(block_hash, HASH_LENGTH * 2);
    if (block_hash_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    memcpy(sigbuf, block_hash_u, HASH_LENGTH);
    sigbuf += HASH_LENGTH;
    free(block_hash_u);
    // Reserved
    memcpy(sigbuf, reserved_str.c_str(), reserved_str.size());
    sigbuf += reserved_str.size();
    // Files size
    memcpy(sigbuf, files_size_str.c_str(), files_size_str.size());
    sigbuf += files_size_str.size();
    // Reserved root
    memcpy(sigbuf, srd_root, sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Files root
    memcpy(sigbuf, files_root, sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Added files
    memcpy(sigbuf, added_files.c_str(), added_files.size());
    sigbuf += added_files.size();
    // Deleted files
    memcpy(sigbuf, deleted_files.c_str(), deleted_files.size());
    sigbuf += deleted_files.size();

    // Sign work report
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    sgx_ec256_signature_t sgx_sig; 
    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len, &id_key_pair.pri_key, &sgx_sig, ecc_state);
    sgx_ecc256_close_context(ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }

    // Store workreport
    std::string wr_str;
    wr_str.append("{");
    wr_str.append("\"").append(WORKREPORT_PUB_KEY).append("\":")
        .append("\"").append(hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key))).append("\",");
    wr_str.append("\"").append(WORKREPORT_PRE_PUB_KEY).append("\":")
        .append("\"").append(pre_pub_key).append("\",");
    wr_str.append("\"").append(WORKREPORT_BLOCK_HEIGHT).append("\":")
        .append("\"").append(block_height_str).append("\",");
    wr_str.append("\"").append(WORKREPORT_BLOCK_HASH).append("\":")
        .append("\"").append(std::string(block_hash, HASH_LENGTH * 2)).append("\",");
    wr_str.append("\"").append(WORKREPORT_RESERVED).append("\":")
        .append(std::to_string(srd_workload)).append(",");
    wr_str.append("\"").append(WORKREPORT_FILES_SIZE).append("\":")
        .append(std::to_string(files_size)).append(",");
    wr_str.append("\"").append(WORKREPORT_RESERVED_ROOT).append("\":")
        .append("\"").append(hexstring_safe(srd_root, HASH_LENGTH)).append("\",");
    wr_str.append("\"").append(WORKREPORT_FILES_ROOT).append("\":")
        .append("\"").append(hexstring_safe(files_root, HASH_LENGTH)).append("\",");
    wr_str.append("\"").append(WORKREPORT_FILES_ADDED).append("\":")
        .append(added_files).append(",");
    wr_str.append("\"").append(WORKREPORT_FILES_DELETED).append("\":")
        .append(deleted_files).append(",");
    wr_str.append("\"").append(WORKREPORT_SIG).append("\":")
        .append("\"").append(hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t))).append("\"");
    wr_str.append("}");
    g_work_report_test = wr_str;

    return crust_status;
}
