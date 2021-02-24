#include "Validator.h"

// Srd related variables
std::vector<uint8_t *> g_del_srd_v;
sgx_thread_mutex_t g_del_srd_v_mutex = SGX_THREAD_MUTEX_INITIALIZER;
std::map<int, uint8_t *> g_validate_srd_m;
std::map<int, uint8_t *>::const_iterator g_validate_srd_m_iter;
sgx_thread_mutex_t g_validate_srd_m_iter_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint32_t g_validated_srd_num = 0;
sgx_thread_mutex_t g_validated_srd_num_mutex = SGX_THREAD_MUTEX_INITIALIZER;
// File related method and variables
crust_status_t validate_real_file(uint8_t *p_sealed_data, size_t sealed_data_size);
std::unordered_set<uint32_t> g_del_files_idx_us;
sgx_thread_mutex_t g_del_files_idx_us_mutex = SGX_THREAD_MUTEX_INITIALIZER;
std::map<uint32_t, json::JSON> g_validate_files_m;
std::map<uint32_t, json::JSON>::const_iterator g_validate_files_m_iter;
sgx_thread_mutex_t g_validate_files_m_iter_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint32_t g_validated_files_num = 0;
sgx_thread_mutex_t g_validated_files_num_mutex = SGX_THREAD_MUTEX_INITIALIZER;
uint32_t g_validate_random = 0;
sgx_thread_mutex_t g_validate_random_mutex = SGX_THREAD_MUTEX_INITIALIZER;

/**
 * @description: validate srd disk
 */
void validate_srd()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&wl->srd_mutex);
    size_t srd_validate_num = std::max((size_t)(wl->srd_hashs.size() * SRD_VALIDATE_RATE), (size_t)SRD_VALIDATE_MIN_NUM);
    srd_validate_num = std::min(srd_validate_num, wl->srd_hashs.size());
    // Randomly choose validate srd files
    uint32_t rand_val;
    uint32_t rand_idx = 0;
    if (srd_validate_num >= wl->srd_hashs.size())
    {
        for (size_t i = 0; i < wl->srd_hashs.size(); i++)
        {
            g_validate_srd_m[i] = wl->srd_hashs[i];
        }
    }
    else
    {
        for (size_t i = 0; i < srd_validate_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_idx = rand_val % wl->srd_hashs.size();
            g_validate_srd_m[rand_idx] = wl->srd_hashs[rand_idx];
        }
    }
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Validate SRD ----- //
    g_validate_srd_m_iter = g_validate_srd_m.begin();
    sgx_status_t sgx_status = SGX_SUCCESS;
    // Generate validate random flag
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    sgx_read_rand((uint8_t *)&g_validate_random, sizeof(g_validate_random));
    sgx_thread_mutex_unlock(&g_validate_random_mutex);
    for (size_t i = 0; i < g_validate_srd_m.size(); i++)
    {
        // If ocall failed, add srd to deleted buffer
        if (SGX_SUCCESS != (sgx_status = ocall_recall_validate_srd()))
        {
            log_err("Invoke validate srd task failed! Error code:%lx\n", sgx_status);
            // Increase validate srd iterator
            sgx_thread_mutex_lock(&g_validate_srd_m_iter_mutex);
            uint32_t g_hash_index = g_validate_srd_m_iter->first;
            uint8_t *p_g_hash = g_validate_srd_m_iter->second;
            g_validate_srd_m_iter++;
            sgx_thread_mutex_unlock(&g_validate_srd_m_iter_mutex);
            // Increase validated srd finish num
            sgx_thread_mutex_lock(&g_validated_srd_num_mutex);
            g_validated_srd_num++;
            sgx_thread_mutex_unlock(&g_validated_srd_num_mutex);
            // Push current g_hash to delete buffer
            sgx_thread_mutex_lock(&g_del_srd_v_mutex);
            g_del_srd_v.push_back(p_g_hash);
            sgx_thread_mutex_unlock(&g_del_srd_v_mutex);
            wl->add_srd_to_deleted_buffer(g_hash_index);
        }
    }

    // Wait srd validation complete
    size_t wait_interval = 1000;
    size_t wait_time = 0;
    size_t timeout = REPORT_SLOT * BLOCK_INTERVAL * 1000000;
    while (true)
    {
        SafeLock sl(g_validated_srd_num_mutex);
        sl.lock();
        if (g_validated_srd_num >= g_validate_srd_m.size())
        {
            wl->report_add_validated_srd_proof();
            break;
        }
        sl.unlock();
        ocall_usleep(wait_interval);
        // Check if timeout
        wait_time += wait_interval;
        if (wait_time > timeout)
        {
            break;
        }
    }

    // Delete failed srd metadata
    for (auto hash : g_del_srd_v)
    {
        std::string del_path = hexstring_safe(hash, HASH_LENGTH);
        ocall_delete_folder_or_file(&crust_status, del_path.c_str(), STORE_TYPE_SRD);
    }

    // Clear deleted srd buffer
    g_del_srd_v.clear();

    // Clear validate buffer
    g_validate_srd_m.clear();

    // Reset index and finish number
    g_validated_srd_num = 0;
}

/**
 * @description: Validate srd real
 */
void validate_srd_real()
{
    // Get current validate random
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    uint32_t cur_validate_random = g_validate_random;
    sgx_thread_mutex_unlock(&g_validate_random_mutex);

    // Get srd info from iterator
    SafeLock sl_iter(g_validate_srd_m_iter_mutex);
    sl_iter.lock();
    if (g_validate_srd_m_iter == g_validate_srd_m.end())
    {
        return;
    }
    uint32_t g_hash_index = g_validate_srd_m_iter->first;
    uint8_t *p_g_hash = g_validate_srd_m_iter->second;
    g_validate_srd_m_iter++;
    sl_iter.unlock();

    // Get g_hash corresponding path
    std::string g_hash = hexstring_safe(p_g_hash, HASH_LENGTH);
    Workload *wl = Workload::get_instance();
    bool deleted = false;

    Defer finish_defer([&cur_validate_random, &deleted, &p_g_hash, &g_hash_index, &wl](void) {
        // Get current validate random
        sgx_thread_mutex_lock(&g_validate_random_mutex);
        uint32_t now_validate_srd_random = g_validate_random;
        sgx_thread_mutex_unlock(&g_validate_random_mutex);
        // Check if validata random is the same
        if (cur_validate_random == now_validate_srd_random)
        {
            sgx_thread_mutex_lock(&g_validated_srd_num_mutex);
            g_validated_srd_num++;
            sgx_thread_mutex_unlock(&g_validated_srd_num_mutex);
            // Deal with result
            if (deleted)
            {
                sgx_thread_mutex_lock(&g_del_srd_v_mutex);
                g_del_srd_v.push_back(p_g_hash);
                sgx_thread_mutex_unlock(&g_del_srd_v_mutex);
                wl->add_srd_to_deleted_buffer(g_hash_index);
            }
        }
    });

    // Get M hashs
    uint8_t *m_hashs_org = NULL;
    size_t m_hashs_size = 0;
    srd_get_file(get_m_hashs_file_path(g_hash.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
    if (m_hashs_org == NULL)
    {
        if (!wl->add_srd_to_deleted_buffer(g_hash_index))
        {
            return;
        }
        log_err("Get m hashs file(%s) failed.\n", g_hash.c_str());
        deleted = true;
        return;
    }
    Defer hashs_org_defer([&m_hashs_org](void) {
        free(m_hashs_org);
    });

    uint8_t *m_hashs = (uint8_t *)enc_malloc(m_hashs_size);
    if (m_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return;
    }
    Defer hashs_defer([&m_hashs](void) {
        free(m_hashs);
    });
    memset(m_hashs, 0, m_hashs_size);
    memcpy(m_hashs, m_hashs_org, m_hashs_size);

    // Compare M hashs
    sgx_sha256_hash_t m_hashs_sha256;
    sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_sha256);
    if (memcmp(p_g_hash, m_hashs_sha256, HASH_LENGTH) != 0)
    {
        log_err("Wrong m hashs file(%s).\n", g_hash.c_str());
        deleted = true;
        return;
    }

    // Get leaf data
    uint32_t rand_val;
    sgx_read_rand((uint8_t*)&rand_val, 4);
    size_t srd_block_index = rand_val % SRD_RAND_DATA_NUM;
    std::string leaf_path = get_leaf_path(g_hash.c_str(), srd_block_index, m_hashs + srd_block_index * HASH_LENGTH);
    uint8_t *leaf_data = NULL;
    size_t leaf_data_len = 0;
    srd_get_file(leaf_path.c_str(), &leaf_data, &leaf_data_len);
    if (leaf_data == NULL)
    {
        if (!wl->add_srd_to_deleted_buffer(g_hash_index))
        {
            return;
        }
        log_err("Get leaf file(%s) failed.\n", g_hash.c_str());
        deleted = true;
        return;
    }
    Defer leaf_defer([&leaf_data](void) {
        free(leaf_data);
    });

    // Compare leaf data
    sgx_sha256_hash_t leaf_hash;
    sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_hash);
    if (memcmp(m_hashs + srd_block_index * HASH_LENGTH, leaf_hash, HASH_LENGTH) != 0)
    {
        log_err("Wrong leaf data hash '%s'(file path:%s).\n", g_hash.c_str(), g_hash.c_str());
        deleted = true;
    }
}

/**
 * @description: Validate Meaningful files
 */
void validate_meaningful_file()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Lock wl->sealed_files
    sgx_thread_mutex_lock(&wl->file_mutex);
    // Get to be checked files indexes
    size_t check_file_num = std::max((size_t)(wl->sealed_files.size() * MEANINGFUL_VALIDATE_RATE), (size_t)MEANINGFUL_VALIDATE_MIN_NUM);
    check_file_num = std::min(check_file_num, wl->sealed_files.size());
    uint32_t rand_val;
    size_t rand_index = 0;
    if (check_file_num >= wl->sealed_files.size())
    {
        for (size_t i = 0; i < wl->sealed_files.size(); i++)
        {
            g_validate_files_m[i] = wl->sealed_files[i];
        }
    }
    else
    {
        for (size_t i = 0; i < check_file_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_index = rand_val % wl->sealed_files.size();
            g_validate_files_m[rand_index] = wl->sealed_files[rand_index];
        }
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    // ----- Validate file ----- //
    // Used to indicate which meaningful file status has been changed
    // If new file hasn't been verified, skip this validation
    sgx_status_t sgx_status = SGX_SUCCESS;
    g_validate_files_m_iter = g_validate_files_m.begin();
    // Generate validate random flag
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    sgx_read_rand((uint8_t *)&g_validate_random, sizeof(g_validate_random));
    sgx_thread_mutex_unlock(&g_validate_random_mutex);
    for (size_t i = 0; i < g_validate_files_m.size(); i++)
    {
        // If ocall failed, add file to deleted buffer
        if (SGX_SUCCESS != (sgx_status = ocall_recall_validate_file()))
        {
            log_err("Invoke validate file task failed! Error code:%lx\n", sgx_status);
            // Get current file info
            sgx_thread_mutex_lock(&g_validate_files_m_iter_mutex);
            uint32_t file_idx = g_validate_files_m_iter->first;
            json::JSON file = g_validate_files_m_iter->second;
            g_validate_files_m_iter++;
            sgx_thread_mutex_unlock(&g_validate_files_m_iter_mutex);
            // Increase validated files number
            sgx_thread_mutex_lock(&g_validated_files_num_mutex);
            g_validated_files_num++;
            sgx_thread_mutex_unlock(&g_validated_files_num_mutex);
            // Add file to deleted buffer
            sgx_thread_mutex_lock(&g_del_files_idx_us_mutex);
            g_del_files_idx_us.insert(file_idx);
            sgx_thread_mutex_unlock(&g_del_files_idx_us_mutex);
        }

        if (!wl->get_report_file_flag())
        {
            break;
        }
    }

    // If report file flag is true, check if validating file is complete
    size_t wait_interval = 1000;
    size_t wait_time = 0;
    size_t timeout = REPORT_SLOT * BLOCK_INTERVAL * 1000000;
    while (true)
    {
        SafeLock sl(g_validated_files_num_mutex);
        sl.lock();
        if (g_validated_files_num >= g_validate_files_m.size())
        {
            wl->report_add_validated_file_proof();
            break;
        }
        sl.unlock();
        ocall_usleep(wait_interval);
        // Check if timeout
        wait_time += wait_interval;
        if (wait_time > timeout)
        {
            break;
        }
    }

    // Change file status
    if (g_del_files_idx_us.size() > 0)
    {
        sgx_thread_mutex_lock(&wl->file_mutex);
        for (auto del_index : g_del_files_idx_us)
        {
            size_t index = 0;
            std::string cid = g_validate_files_m[del_index][FILE_CID].ToString();
            if(wl->is_file_dup(cid, index))
            {
                long cur_block_num = wl->sealed_files[index][CHAIN_BLOCK_NUMBER].ToInt();
                long val_block_num = g_validate_files_m[del_index][CHAIN_BLOCK_NUMBER].ToInt();
                // We can get original file and new sealed file(this situation maybe exist)
                // If these two files are not the same one, cannot delete the file
                if (cur_block_num == val_block_num)
                {
                    log_info("File status changed, hash: %s status: valid -> lost, will be deleted\n", cid.c_str());
                    // Change file status
                    wl->sealed_files[index][FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                    // Delete real file
                    ocall_ipfs_del_all(&crust_status, cid.c_str());
                    // Reduce valid file
                    wl->set_wl_spec(FILE_STATUS_VALID, -g_validate_files_m[index][FILE_SIZE].ToInt());
                }
            }
            else
            {
                log_err("Deal with bad file(%s) failed!\n", cid.c_str());
            }
        }
        sgx_thread_mutex_unlock(&wl->file_mutex);
    }

    // Clear validate buffer
    g_validate_files_m.clear();

    // Clear deleted file buffer
    g_del_files_idx_us.clear();

    // Reset validate file finish flag
    g_validated_files_num = 0;
}

/**
 * @description: Validate meaningful files real
 */
void validate_meaningful_file_real()
{
    Workload *wl = Workload::get_instance();
    if (!wl->get_report_file_flag())
    {
        return;
    }

    // Get current validate random
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    uint32_t cur_validate_random = g_validate_random;
    sgx_thread_mutex_unlock(&g_validate_random_mutex);

    // Get file info from iterator
    SafeLock sl_iter(g_validate_files_m_iter_mutex);
    sl_iter.lock();
    if (g_validate_files_m_iter == g_validate_files_m.end())
    {
        return;
    }
    uint32_t file_idx = g_validate_files_m_iter->first;
    json::JSON file = g_validate_files_m_iter->second;
    g_validate_files_m_iter++;
    sl_iter.unlock();

    bool deleted = false;

    Defer finish_defer([&cur_validate_random, &deleted, &file_idx, &wl](void) {
        // Get current validate random
        sgx_thread_mutex_lock(&g_validate_random_mutex);
        uint32_t now_validate_random = g_validate_random;
        sgx_thread_mutex_unlock(&g_validate_random_mutex);
        // Check if validate random is the same
        if (cur_validate_random == now_validate_random)
        {
            sgx_thread_mutex_lock(&g_validated_files_num_mutex);
            if (!wl->get_report_file_flag())
            {
                g_validated_files_num = g_validate_files_m.size();
            }
            else
            {
                g_validated_files_num++;
            }
            sgx_thread_mutex_unlock(&g_validated_files_num_mutex);
            // Deal with result
            if (deleted && wl->get_report_file_flag())
            {
                sgx_thread_mutex_lock(&g_del_files_idx_us_mutex);
                g_del_files_idx_us.insert(file_idx);
                sgx_thread_mutex_unlock(&g_del_files_idx_us_mutex);
            }
        }
    });

    // If file status is not FILE_STATUS_VALID, return
    auto status = file[FILE_STATUS];
    if (status.get_char(CURRENT_STATUS) == FILE_STATUS_PENDING
            || status.get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
    {
        return;
    }

    std::string root_cid = file[FILE_CID].ToString();
    std::string root_hash = file[FILE_HASH].ToString();
    size_t file_block_num = file[FILE_BLOCK_NUM].ToInt();
    // Get tree string
    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = persist_get_unsafe(root_cid, &p_data, &data_len);
    if (CRUST_SUCCESS != crust_status)
    {
        if (wl->is_in_deleted_file_buffer(root_cid))
        {
            return;
        }
        log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_cid.c_str());
        if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            deleted = true;
        }
        if (p_data != NULL)
        {
            free(p_data);
            p_data = NULL;
        }
        return;
    }
    // Validate merkle tree
    std::string tree_str(reinterpret_cast<const char *>(p_data), data_len);
    if (p_data != NULL)
    {
        free(p_data);
        p_data = NULL;
    }
    json::JSON tree_json = json::JSON::Load(tree_str);
    bool valid_tree = true;
    if (root_hash.compare(tree_json[MT_HASH].ToString()) != 0)
    {
        log_err("File:%s merkle tree is not valid!Root hash doesn't equal!\n", root_cid.c_str());
        valid_tree = false;
    }
    if (CRUST_SUCCESS != (crust_status = validate_merkletree_json(tree_json)))
    {
        log_err("File:%s merkle tree is not valid!Invalid merkle tree,error code:%lx\n", root_cid.c_str(), crust_status);
        valid_tree = false;
    }
    if (!valid_tree)
    {
        if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            deleted = true;
        }
        return;
    }

    // ----- Validate MerkleTree ----- //
    // Get to be checked block index
    std::set<size_t> block_idx_s;
    size_t tmp_idx = 0;
    uint32_t rand_val;
    for (size_t i = 0; i < MEANINGFUL_VALIDATE_MIN_BLOCK_NUM && i < file_block_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        tmp_idx = rand_val % file_block_num;
        if (block_idx_s.find(tmp_idx) == block_idx_s.end())
        {
            block_idx_s.insert(tmp_idx);
        }
    }
    // Do check
    // Note: should store serialized tree structure as "cid":x,"hash":"xxxxx"
    // be careful to keep "cid", "hash" sequence
    size_t pos = 0;
    std::string dhash_tag(MT_DATA_HASH "\":\"");
    size_t cur_block_idx = 0;
    for (auto check_block_idx : block_idx_s)
    {
        // Get leaf node position
        do
        {
            pos = tree_str.find(dhash_tag, pos);
            if (pos == tree_str.npos)
            {
                break;
            }
            pos += dhash_tag.size();
        } while (cur_block_idx++ < check_block_idx);
        if (pos == tree_str.npos)
        {
            log_err("Find file(%s) leaf node cid failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                deleted = true;
            }
            break;
        }
        // Get current node hash
        std::string leaf_hash = tree_str.substr(pos, HASH_LENGTH * 2);
        // Compute current node hash by data
        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_size = 0;
        std::string leaf_path = root_cid + "/" + leaf_hash;
        crust_status = storage_get_file(leaf_path.c_str(), &p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            if (p_sealed_data != NULL)
            {
                free(p_sealed_data);
            }
            if (wl->is_in_deleted_file_buffer(root_cid))
            {
                break;
            }
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                deleted = true;
            }
            log_err("Get file(%s) block:%ld failed!\n", root_cid.c_str(), check_block_idx);
            break;
        }
        // Validate sealed hash
        sgx_sha256_hash_t got_hash;
        sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
        uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
        if (leaf_hash_u == NULL)
        {
            log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
            free(p_sealed_data);
            continue;
        }
        int memret = memcmp(leaf_hash_u, got_hash, HASH_LENGTH);
        free(leaf_hash_u);
        if (memret != 0)
        {
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                log_err("File(%s) Index:%ld block hash is not expected!\n", root_cid.c_str(), check_block_idx);
                log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                log_err("Org hash : %s\n", leaf_hash.c_str());
                deleted = true;
            }
            free(p_sealed_data);
            break;
        }
        // Validate real file piece
        crust_status = validate_real_file(p_sealed_data, sealed_data_size);
        free(p_sealed_data);
        if (CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SERVICE_UNAVAILABLE == crust_status)
            {
                wl->set_report_file_flag(false);
                return;
            }
            else
            {
                log_err("Get file(%s) block failed! Error code:%lx\n", root_cid.c_str(), crust_status);
                deleted = true;
            }
            break;
        }
    }
}

/**
 * @description: Validate real ipfs file
 * @param p_sealed_data -> Pointer to sealed data
 * @param sealed_data_size -> Sealed data size
 * @return: Validate result
 */
crust_status_t validate_real_file(uint8_t *p_sealed_data, size_t sealed_data_size)
{
    if (sealed_data_size <= 0)
    {
        return CRUST_SUCCESS;
    }

    crust_status_t crust_status = CRUST_SUCCESS;
    uint8_t *p_unsealed_data = NULL;
    uint8_t *p_got_piece_data = NULL;
    do
    {
        // Unseal data
        uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)p_sealed_data);
        p_unsealed_data = (uint8_t *)enc_malloc(unsealed_data_size);
        if (p_unsealed_data == NULL)
        {
            crust_status = CRUST_MALLOC_FAILED;
            break;
        }
        memset(p_unsealed_data, 0, unsealed_data_size);
        sgx_status_t sgx_status = sgx_unseal_data((sgx_sealed_data_t *)p_sealed_data, NULL, NULL,
                p_unsealed_data, &unsealed_data_size);
        if (SGX_SUCCESS != sgx_status)
        {
            crust_status = CRUST_UNEXPECTED_ERROR;
            break;
        }

        // Choose to be checked file piece
        uint32_t piece_num = 0;
        memcpy(&piece_num, p_unsealed_data, sizeof(uint32_t));
        if (piece_num == 0)
        {
            crust_status = CRUST_UNEXPECTED_ERROR;
            break;
        }
        uint32_t rand_num = 0;
        sgx_read_rand((uint8_t *)&rand_num, sizeof(uint32_t));
        int chk_index = rand_num % piece_num;
        uint32_t chk_spos, chk_epos;
        chk_spos = chk_epos = SEALED_BLOCK_TAG_SIZE;
        do
        {
            chk_spos = chk_epos;
            chk_epos = 0;
            memcpy(&chk_epos, p_unsealed_data + chk_spos, SEALED_BLOCK_TAG_SIZE);
            chk_spos += SEALED_BLOCK_TAG_SIZE;
            chk_epos += chk_spos;
        } while (chk_epos < unsealed_data_size && --chk_index >= 0);

        // ----- Do check ----- //
        // Get cid from unsealed data piece
        size_t real_piece_size = chk_epos - chk_spos;
        uint8_t *p_real_piece_data = p_unsealed_data + chk_spos;
        sgx_sha256_hash_t piece_hash;
        sgx_sha256_msg(p_real_piece_data, real_piece_size, &piece_hash);
        std::string piece_cid = hash_to_cid(reinterpret_cast<const uint8_t *>(&piece_hash));
        // Get related IPFS file data piece
        size_t got_piece_size = 0;
        crust_status = storage_ipfs_get_block(piece_cid.c_str(), &p_got_piece_data, &got_piece_size);
        if (CRUST_SUCCESS != crust_status)
        {
            break;
        }
        // Compare data piece
        if (memcmp(p_real_piece_data, p_got_piece_data, real_piece_size) != 0)
        {
            crust_status = CRUST_UNEXPECTED_ERROR;
            break;
        }
    } while (0);

    if (p_unsealed_data != NULL)
    {
        free(p_unsealed_data);
    }

    if (p_got_piece_data != NULL)
    {
        free(p_got_piece_data);
    }

    return crust_status;
}
