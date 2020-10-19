#include "Report.h"
#include "EJson.h"


/* Indicates whether the current work report is validated */
sgx_thread_mutex_t g_validated_mutex = SGX_THREAD_MUTEX_INITIALIZER;
int validated_proof = 0;
std::string g_work_report;

extern sgx_thread_mutex_t g_srd_mutex;
extern sgx_thread_mutex_t g_checked_files_mutex;
extern sgx_thread_mutex_t g_gen_work_report;

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
bool report_has_validated_proof()
{
    return validated_proof > 0;
}

/**
 * @description: Get generated work report
 * @return: Generated work report
 */
std::string get_generated_work_report()
{
    return g_work_report;
}

/**
 * @description: Get signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @return: sign status
 */
crust_status_t get_signed_work_report(const char *block_hash, size_t block_height, bool locked /*=true*/)
{
    // Judge whether the current data is validated 
    if (!report_has_validated_proof())
    {
        return CRUST_WORK_REPORT_NOT_VALIDATED;
    }

    // Judge whether block height is expired
    if (block_height == 0 || block_height - id_get_report_height() < ERA_LENGTH)
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }

    Workload *wl = Workload::get_instance();
    // The first report after restart will not be processed
    if (id_just_after_restart())
    {
        id_set_just_after_restart(false);
        wl->set_report_flag(true);
        return CRUST_FIRST_WORK_REPORT_AFTER_REPORT;
    }

    // Have files and no karst
    if (!wl->get_report_flag())
    {
        wl->set_report_flag(true);
        return CRUST_NO_KARST;
    }

    if (locked)
    {
        sgx_thread_mutex_lock(&g_gen_work_report);
    }

    ecc_key_pair id_key_pair = id_get_key_pair();
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status;
    size_t hashs_len = 0;
    size_t files_buffer_len = 0;
    sgx_sha256_hash_t files_root;
    long long files_size = 0;
    size_t files_offset = 0;
    uint8_t *files_buffer = NULL;
    std::string added_files;
    std::string deleted_files;
    size_t files_acc = 0;
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_ec256_signature_t sgx_sig; 
    std::string wr_str;
    uint8_t *block_hash_u = NULL;
    std::string pre_pub_key;
    size_t pre_pub_key_size = 0;
    std::string block_height_str;
    std::string reserved_str;
    std::string files_size_str;
    size_t sigbuf_len = 0;
    uint8_t *sigbuf = NULL;
    uint8_t *p_sigbuf = NULL;
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
        crust_status =  CRUST_MALLOC_FAILED;
        goto cleanup;
    }
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
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    // Deleted invalid file item
    for (auto it = wl->checked_files.begin(); it != wl->checked_files.end();)
    {
        std::string status = (*it)[FILE_STATUS].ToString();
        if (status[CURRENT_STATUS] == FILE_STATUS_VALID)
        {
            files_buffer_len += HASH_LENGTH;
        }
        if ((status[CURRENT_STATUS] == FILE_STATUS_DELETED && status[ORIGIN_STATUS] == FILE_STATUS_LOST)
                || (status[CURRENT_STATUS] == FILE_STATUS_DELETED && status[ORIGIN_STATUS] == FILE_STATUS_DELETED)
                || (status[CURRENT_STATUS] == FILE_STATUS_DELETED && status[ORIGIN_STATUS] == FILE_STATUS_UNCONFIRMED))
        {
            it = wl->checked_files.erase(it);
        }
        else
        {
            it++;
        }
    }
    // Clear reported_files_idx
    wl->reported_files_idx.clear();
    // Generate files information
    if (files_buffer_len != 0)
    {
        files_buffer = (uint8_t *)enc_malloc(files_buffer_len);
        if (files_buffer == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            goto cleanup;
        }
        memset(files_buffer, 0, files_buffer_len);
    }
    added_files = "[";
    deleted_files = "[";
    files_acc = 0;
    for (uint32_t i = 0; i < wl->checked_files.size(); i++)
    {
        auto status = &wl->checked_files[i][FILE_STATUS];
        // Write current status to waiting status
        status->set_char(WAITING_STATUS, status->get_char(CURRENT_STATUS));
        // Calculate old files size
        if (status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID)
        {
            files_size += wl->checked_files[i][FILE_OLD_SIZE].ToInt();
        }
        // Calculate files(valid) root hash
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            memcpy(files_buffer + files_offset, wl->checked_files[i][FILE_HASH].ToBytes(), HASH_LENGTH);
            files_offset += HASH_LENGTH;
        }
        // Generate report files queue
        if (files_acc < WORKREPORT_FILE_LIMIT)
        {
            if ((status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID && status->get_char(ORIGIN_STATUS) == FILE_STATUS_UNCONFIRMED)
                    || (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID && status->get_char(ORIGIN_STATUS) == FILE_STATUS_LOST)
                    || (status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST && status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID)
                    || (status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED && status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID))
            {
                std::string file_str;
                file_str.append("{\"").append(FILE_HASH).append("\":")
                    .append("\"").append(wl->checked_files[i][FILE_OLD_HASH].ToString()).append("\",");
                file_str.append("\"").append(FILE_SIZE).append("\":")
                    .append(std::to_string(wl->checked_files[i][FILE_OLD_SIZE].ToInt())).append("}");
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST || status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
                {
                    if (deleted_files.size() != 1)
                    {
                        deleted_files.append(",");
                    }
                    deleted_files.append(file_str);
                    // Update new files size
                    files_size -= wl->checked_files[i][FILE_OLD_SIZE].ToInt();
                }
                else if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    if (added_files.size() != 1)
                    {
                        added_files.append(",");
                    }
                    added_files.append(file_str);
                    // Update new files size
                    files_size += wl->checked_files[i][FILE_OLD_SIZE].ToInt();
                }
                wl->reported_files_idx.insert(i);
                files_acc++;
            }
        }
    }
    added_files.append("]");
    deleted_files.append("]");
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
    if (files_offset == 0)
    {
        memset(&files_root, 0, sizeof(sgx_sha256_hash_t));
    }
    else
    {
        sgx_sha256_msg(files_buffer, (uint32_t)files_offset, &files_root);
        free(files_buffer);
    }

    // ----- Create signature data ----- //
    if (wl->is_upgrade())
    {
        pre_pub_key_size = sizeof(wl->pre_pub_key);
        pre_pub_key = hexstring_safe(&wl->pre_pub_key, sizeof(wl->pre_pub_key));
    }
    block_height_str = std::to_string(block_height);
    reserved_str = std::to_string(srd_workload);
    files_size_str = std::to_string(files_size);
    sigbuf_len = sizeof(id_key_pair.pub_key) 
        + pre_pub_key_size
        + block_height_str.size()
        + HASH_LENGTH
        + reserved_str.size()
        + files_size_str.size()
        + sizeof(sgx_sha256_hash_t)
        + sizeof(sgx_sha256_hash_t)
        + added_files.size()
        + deleted_files.size();
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    p_sigbuf = NULL;
    if (sigbuf == NULL)
    {
        log_err("Malloc memory failed!\n");
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
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
    block_hash_u = hex_string_to_bytes(block_hash, HASH_LENGTH * 2);
    if (block_hash_u == NULL)
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
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
    store_large_data(reinterpret_cast<const uint8_t *>(wr_str.c_str()), wr_str.size(), ocall_store_workreport, wl->ocall_wr_mutex);
    g_work_report = wr_str;

    // Reset meaningful data
    wl->set_report_flag(true);

    // Set report height
    id_set_report_height(block_height);


cleanup:
    if (locked)
    {
        sgx_thread_mutex_unlock(&g_gen_work_report);
    }

    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    free(p_sigbuf);

    report_reduce_validated_proof();
    id_set_just_after_restart(false);
    return crust_status;
}
