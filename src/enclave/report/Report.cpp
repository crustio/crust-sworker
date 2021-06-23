#include "Report.h"

extern sgx_thread_mutex_t g_gen_work_report;

/**
 * @description: Generate and upload signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @param wait_time -> Waiting time before upload
 * @param is_upgrading -> Is this upload kind of upgrade
 * @param locked -> Lock this upload or not
 * @return: sign status
 */
crust_status_t gen_and_upload_work_report(const char *block_hash, size_t block_height, long wait_time, bool is_upgrading, bool locked)
{
    SafeLock gen_sl(g_gen_work_report);
    if (locked)
    {
        gen_sl.lock();
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    // Wait indicated time
    if (wait_time != 0)
    {
        ocall_usleep(wait_time * 1000000);
    }

    // Generate work report
    if (CRUST_SUCCESS != (crust_status = gen_work_report(block_hash, block_height, is_upgrading)))
    {
        return crust_status;
    }

    // Upload work report
    ocall_upload_workreport(&crust_status);

    // Confirm work report result
    if (CRUST_SUCCESS == crust_status)
    {
        Workload::get_instance()->handle_report_result();
    }

    return crust_status;
}

/**
 * @description: Get signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height -> block height
 * @param is_upgrading -> Check if this turn is uprade
 * @return: sign status
 */
crust_status_t gen_work_report(const char *block_hash, size_t block_height, bool is_upgrading)
{
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    // Judge whether block height is expired
    if (block_height == 0 || wl->get_report_height() + REPORT_SLOT > block_height)
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }

    Defer defer_status([&wl, &block_height](void) {
        wl->set_report_height(block_height);
        wl->set_report_file_flag(true);
        wl->reduce_restart_flag();
        wl->report_reset_validated_proof();
    });

    if (wl->get_restart_flag())
    {
        // The first 4 report after restart will not be processed
        return CRUST_FIRST_WORK_REPORT_AFTER_REPORT;
    }
    if (!wl->get_report_file_flag())
    {
        // Have files and no IPFS
        return CRUST_SERVICE_UNAVAILABLE;
    } 
    if (!wl->report_has_validated_proof())
    {
        // Judge whether the current data is validated 
        return CRUST_WORK_REPORT_NOT_VALIDATED;
    }

    ecc_key_pair id_key_pair = wl->get_key_pair();
    sgx_status_t sgx_status;

    // ----- Get srd info ----- //
    SafeLock srd_sl(wl->srd_mutex);
    srd_sl.lock();
    // Compute srd root hash
    size_t srd_workload;
    sgx_sha256_hash_t srd_root;
    size_t g_hashs_num = wl->srd_hashs.size();
    if (g_hashs_num > 0)
    {
        uint8_t *srd_data = (uint8_t *)enc_malloc(g_hashs_num * SRD_LENGTH);
        if (srd_data == NULL)
        {
            log_err("Malloc memory failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        size_t hashs_offset = 0;
        for (auto g_hash : wl->srd_hashs)
        {
            memcpy(srd_data + hashs_offset, g_hash, SRD_LENGTH);
            hashs_offset += SRD_LENGTH;
        }
        // Generate srd information
        srd_workload = g_hashs_num * 1024 * 1024 * 1024;
        sgx_sha256_msg(srd_data, (uint32_t)(g_hashs_num * SRD_LENGTH), &srd_root);
        free(srd_data);
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
    json::JSON added_files;
    json::JSON deleted_files;
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
                        || (status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST && status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID)
                        || (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID && status->get_char(ORIGIN_STATUS) == FILE_STATUS_LOST)
                        || (status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED && status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID))
                {
                    json::JSON file_json;
                    file_json[FILE_CID] = wl->sealed_files[i][FILE_CID].ToString();
                    file_json[FILE_SIZE] = wl->sealed_files[i][FILE_SIZE].ToInt();
                    file_json[FILE_CHAIN_BLOCK_NUM] = wl->sealed_files[i][FILE_CHAIN_BLOCK_NUM].ToInt();
                    if (status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED
                            || status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST)
                    {
                        deleted_files.append(file_json);
                        // Update new files size
                        files_size -= wl->sealed_files[i][FILE_SIZE].ToInt();
                    }
                    else if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                    {
                        added_files.append(file_json);
                        // Update new files size
                        files_size += wl->sealed_files[i][FILE_SIZE].ToInt();
                    }
                    wl->reported_files_idx.insert(wl->sealed_files[i][FILE_CID].ToString());
                    reported_files_acc++;
                }
            }
        }
    }
    // Generate files information
    size_t files_root_buffer_len = report_valid_idx_v.size() * HASH_LENGTH;
    sgx_sha256_hash_t files_root;
    if (files_root_buffer_len > 0)
    {
        uint8_t *files_root_buffer = (uint8_t *)enc_malloc(files_root_buffer_len);
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
    std::vector<uint8_t> sig_buffer;
    // Current public key
    vector_end_insert(sig_buffer, reinterpret_cast<const uint8_t *>(&id_key_pair.pub_key), sizeof(id_key_pair.pub_key));
    // Previous public key
    if (wl->is_upgrade())
    {
        vector_end_insert(sig_buffer, reinterpret_cast<const uint8_t *>(&wl->pre_pub_key), pre_pub_key_size);
    }
    // Block height
    vector_end_insert(sig_buffer, block_height_str);
    // Block hash
    uint8_t *block_hash_u = hex_string_to_bytes(block_hash, HASH_LENGTH * 2);
    if (block_hash_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    vector_end_insert(sig_buffer, block_hash_u, HASH_LENGTH);
    free(block_hash_u);
    // Reserved
    vector_end_insert(sig_buffer, reserved_str);
    // Files size
    vector_end_insert(sig_buffer, files_size_str);
    // Reserved root
    vector_end_insert(sig_buffer, srd_root, sizeof(sgx_sha256_hash_t));
    // Files root
    vector_end_insert(sig_buffer, files_root, sizeof(sgx_sha256_hash_t));
    // Added files
    do
    {
        crust_status_t ret = CRUST_SUCCESS;
        std::vector<uint8_t> added_data = added_files.dump_vector(&ret);
        vector_end_insert(sig_buffer, added_data.data(), added_data.size());
    } while (0);
    // Deleted files
    do
    {
        crust_status_t ret = CRUST_SUCCESS;
        std::vector<uint8_t> deleted_data = deleted_files.dump_vector(&ret);
        vector_end_insert(sig_buffer, deleted_data.data(), deleted_data.size());
    } while (0);

    // Sign work report
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    sgx_ec256_signature_t sgx_sig; 
    sgx_status = sgx_ecdsa_sign(sig_buffer.data(), sig_buffer.size(), &id_key_pair.pri_key, &sgx_sig, ecc_state);
    sgx_ecc256_close_context(ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }

    // Store workreport
    std::vector<uint8_t> wr_data;
    do
    {
        json::JSON wr_json;
        wr_json[WORKREPORT_PUB_KEY] = hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
        wr_json[WORKREPORT_PRE_PUB_KEY] = pre_pub_key;
        wr_json[WORKREPORT_BLOCK_HEIGHT] = block_height_str;
        wr_json[WORKREPORT_BLOCK_HASH] = std::string(block_hash, HASH_LENGTH * 2);
        wr_json[WORKREPORT_RESERVED] = std::to_string(srd_workload);
        wr_json[WORKREPORT_FILES_SIZE] = std::to_string(files_size);
        wr_json[WORKREPORT_RESERVED_ROOT] = hexstring_safe(srd_root, HASH_LENGTH);
        wr_json[WORKREPORT_FILES_ROOT] = hexstring_safe(files_root, HASH_LENGTH);
        wr_json[WORKREPORT_FILES_ADDED] = added_files;
        wr_json[WORKREPORT_FILES_DELETED] = deleted_files;
        wr_json[WORKREPORT_SIG] = hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t)).append("\"}");
        wr_data = wr_json.dump_vector(&crust_status);
        if (CRUST_SUCCESS != crust_status)
        {
            return crust_status;
        }
    } while (0);

    return safe_ocall_store2(OCALL_STORE_WORKREPORT, wr_data.data(), wr_data.size());
}
