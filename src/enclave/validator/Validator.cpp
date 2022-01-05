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
std::vector<json::JSON *> g_changed_files_v;
sgx_thread_mutex_t g_changed_files_v_mutex = SGX_THREAD_MUTEX_INITIALIZER;
std::map<std::string, json::JSON> g_validate_files_m;
std::map<std::string, json::JSON>::const_iterator g_validate_files_m_iter;
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
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    Defer def_clean_del_buffer([&wl](void) {
        // Clean deleted srd
        wl->deal_deleted_srd();
    });

    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    sgx_thread_mutex_lock(&wl->srd_mutex);
    std::map<int, uint8_t *> tmp_validate_srd_m;
    size_t srd_validate_num = std::max((size_t)(wl->srd_hashs.size() * SRD_VALIDATE_RATE), (size_t)SRD_VALIDATE_MIN_NUM);
    srd_validate_num = std::min(srd_validate_num, wl->srd_hashs.size());
    // Randomly choose validate srd files
    uint32_t rand_val;
    uint32_t rand_idx = 0;
    if (srd_validate_num >= wl->srd_hashs.size())
    {
        for (size_t i = 0; i < wl->srd_hashs.size(); i++)
        {
            tmp_validate_srd_m[i] = wl->srd_hashs[i];
        }
    }
    else
    {
        for (size_t i = 0; i < srd_validate_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_idx = rand_val % wl->srd_hashs.size();
            tmp_validate_srd_m[rand_idx] = wl->srd_hashs[rand_idx];
        }
    }
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Validate SRD ----- //
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_thread_mutex_lock(&g_validate_srd_m_iter_mutex);
    g_validate_srd_m.insert(tmp_validate_srd_m.begin(), tmp_validate_srd_m.end());
    tmp_validate_srd_m.clear();
    g_validate_srd_m_iter = g_validate_srd_m.begin();
    sgx_thread_mutex_unlock(&g_validate_srd_m_iter_mutex);
    // Generate validate random flag
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    sgx_read_rand((uint8_t *)&g_validate_random, sizeof(g_validate_random));
    sgx_thread_mutex_unlock(&g_validate_random_mutex);
    // Reset index and finish number
    sgx_thread_mutex_lock(&g_validated_srd_num_mutex);
    g_validated_srd_num = 0;
    sgx_thread_mutex_unlock(&g_validated_srd_num_mutex);
    for (size_t i = 0; i < g_validate_srd_m.size(); i++)
    {
        // If ocall failed, add srd to deleted buffer
        if (SGX_SUCCESS != (sgx_status = ocall_recall_validate_srd()))
        {
            log_err("Invoke validate srd task failed! Error code:%lx\n", sgx_status);
            // Increase validate srd iterator
            sgx_thread_mutex_lock(&g_validate_srd_m_iter_mutex);
            uint32_t srd_index = g_validate_srd_m_iter->first;
            uint8_t *p_srd = g_validate_srd_m_iter->second;
            g_validate_srd_m_iter++;
            sgx_thread_mutex_unlock(&g_validate_srd_m_iter_mutex);
            // Increase validated srd finish num
            sgx_thread_mutex_lock(&g_validated_srd_num_mutex);
            g_validated_srd_num++;
            sgx_thread_mutex_unlock(&g_validated_srd_num_mutex);
            // Push current g_hash to delete buffer
            sgx_thread_mutex_lock(&g_del_srd_v_mutex);
            g_del_srd_v.push_back(p_srd);
            sgx_thread_mutex_unlock(&g_del_srd_v_mutex);
            wl->add_srd_to_deleted_buffer(srd_index);
        }
    }

    // Wait srd validation complete
    size_t wait_interval = 1000;
    size_t wait_time = 0;
    size_t timeout = (size_t)REPORT_SLOT * BLOCK_INTERVAL * 1000000;
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
            log_warn("Validate srd timeout which will lead to generating work report failed! Please check your hardware.\n");
            break;
        }
    }

    // Delete failed srd metadata
    sgx_thread_mutex_lock(&g_del_srd_v_mutex);
    for (auto hash : g_del_srd_v)
    {
        std::string del_path = hexstring_safe(hash, SRD_LENGTH);
        ocall_delete_folder_or_file(&crust_status, del_path.c_str(), STORE_TYPE_SRD);
    }
    // Clear deleted srd buffer
    g_del_srd_v.clear();
    sgx_thread_mutex_unlock(&g_del_srd_v_mutex);

    // Clear validate buffer
    sgx_thread_mutex_lock(&g_validate_srd_m_iter_mutex);
    g_validate_srd_m.clear();
    sgx_thread_mutex_unlock(&g_validate_srd_m_iter_mutex);
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
    uint32_t srd_index = g_validate_srd_m_iter->first;
    uint8_t *p_srd = g_validate_srd_m_iter->second;
    g_validate_srd_m_iter++;
    sl_iter.unlock();

    // Get g_hash corresponding path
    std::string srd_hex = hexstring_safe(p_srd, SRD_LENGTH);
    std::string g_hash_hex = srd_hex.substr(UUID_LENGTH * 2 + LAYER_LENGTH * 2, srd_hex.length());
    Workload *wl = Workload::get_instance();
    bool deleted = false;

    Defer finish_defer([&cur_validate_random, &deleted, &p_srd, &srd_index, &wl](void) {
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
                g_del_srd_v.push_back(p_srd);
                sgx_thread_mutex_unlock(&g_del_srd_v_mutex);
                wl->add_srd_to_deleted_buffer(srd_index);
            }
        }
    });

    // Get M hashs
    uint8_t *m_hashs_org = NULL;
    size_t m_hashs_size = 0;
    crust_status_t crust_status = srd_get_file(get_m_hashs_file_path(srd_hex.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
    if (CRUST_SUCCESS != crust_status)
    {
        if (!wl->add_srd_to_deleted_buffer(srd_index))
        {
            return;
        }
        log_err("Get srd(%s) metadata failed, please check your disk. Error code:%lx\n", g_hash_hex.c_str(), crust_status);
        deleted = true;
        return;
    }
    Defer hashs_org_defer([&m_hashs_org](void) { free(m_hashs_org); });

    uint8_t *m_hashs = (uint8_t *)enc_malloc(m_hashs_size);
    if (m_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return;
    }
    Defer hashs_defer([&m_hashs](void) { free(m_hashs); });
    memset(m_hashs, 0, m_hashs_size);
    memcpy(m_hashs, m_hashs_org, m_hashs_size);

    // Compare M hashs
    sgx_sha256_hash_t m_hashs_sha256;
    sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_sha256);
    if (memcmp(p_srd + UUID_LENGTH + LAYER_LENGTH, m_hashs_sha256, HASH_LENGTH) != 0)
    {
        log_err("Wrong srd(%s) metadata.\n", g_hash_hex.c_str());
        deleted = true;
        return;
    }

    // Get leaf data
    uint32_t rand_val;
    sgx_read_rand((uint8_t*)&rand_val, 4);
    size_t srd_block_index = rand_val % SRD_RAND_DATA_NUM;
    std::string leaf_path = get_leaf_path(srd_hex.c_str(), srd_block_index, m_hashs + srd_block_index * HASH_LENGTH);
    uint8_t *leaf_data = NULL;
    size_t leaf_data_len = 0;
    crust_status = srd_get_file(leaf_path.c_str(), &leaf_data, &leaf_data_len);
    if (CRUST_SUCCESS != crust_status)
    {
        if (!wl->add_srd_to_deleted_buffer(srd_index))
        {
            return;
        }
        log_err("Get srd(%s) block(%s) failed. Error code:%x\n", 
                g_hash_hex.c_str(), hexstring_safe(m_hashs + srd_block_index * HASH_LENGTH, HASH_LENGTH).c_str(), crust_status);
        deleted = true;
        return;
    }
    Defer leaf_defer([&leaf_data](void) { free(leaf_data); });

    // Compare leaf data
    sgx_sha256_hash_t leaf_hash;
    sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_hash);
    if (memcmp(m_hashs + srd_block_index * HASH_LENGTH, leaf_hash, HASH_LENGTH) != 0)
    {
        log_err("Wrong srd block data hash '%s'(file path:%s).\n", g_hash_hex.c_str(), g_hash_hex.c_str());
        deleted = true;
    }
}

/**
 * @description: Validate Meaningful files
 */
void validate_meaningful_file()
{
    Workload *wl = Workload::get_instance();

    Defer def_clean_del_buffer([&wl](void) {
        // Clean deleted file
        wl->deal_deleted_file();
    });

    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    // Lock wl->sealed_files
    std::map<std::string, json::JSON> tmp_validate_files_m;
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
            tmp_validate_files_m[wl->sealed_files[i][FILE_CID].ToString()] = wl->sealed_files[i];
        }
    }
    else
    {
        for (size_t i = 0; i < check_file_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_index = rand_val % wl->sealed_files.size();
            tmp_validate_files_m[wl->sealed_files[rand_index][FILE_CID].ToString()] = wl->sealed_files[rand_index];
        }
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    // ----- Validate file ----- //
    // Used to indicate which meaningful file status has been changed
    // If new file hasn't been verified, skip this validation
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_thread_mutex_lock(&g_validate_files_m_iter_mutex);
    g_validate_files_m.insert(tmp_validate_files_m.begin(), tmp_validate_files_m.end());
    tmp_validate_files_m.clear();
    g_validate_files_m_iter = g_validate_files_m.begin();
    sgx_thread_mutex_unlock(&g_validate_files_m_iter_mutex);
    Defer validate_files([](void) {
        // Clear validate buffer
        sgx_thread_mutex_lock(&g_validate_files_m_iter_mutex);
        g_validate_files_m.clear();
        sgx_thread_mutex_unlock(&g_validate_files_m_iter_mutex);
    });
    // Generate validate random flag
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    sgx_read_rand((uint8_t *)&g_validate_random, sizeof(g_validate_random));
    sgx_thread_mutex_unlock(&g_validate_random_mutex);
    // Reset validate file finish flag
    sgx_thread_mutex_lock(&g_validated_files_num_mutex);
    g_validated_files_num = 0;
    sgx_thread_mutex_unlock(&g_validated_files_num_mutex);
    // Check if IPFS is online
    if (g_validate_files_m.size() > 0)
    {
        bool ipfs_ret = false;
        ocall_ipfs_online(&ipfs_ret);
        if (!ipfs_ret)
        {
            wl->set_report_file_flag(false);
        }
    }
    for (size_t i = 0; i < g_validate_files_m.size(); i++)
    {
        // If ocall failed, add file to deleted buffer
        if (SGX_SUCCESS != (sgx_status = ocall_recall_validate_file()))
        {
            log_err("Invoke validate file task failed! Error code:%lx\n", sgx_status);
            // Get current file info
            sgx_thread_mutex_lock(&g_validate_files_m_iter_mutex);
            json::JSON *file = const_cast<json::JSON *>(&g_validate_files_m_iter->second);
            g_validate_files_m_iter++;
            sgx_thread_mutex_unlock(&g_validate_files_m_iter_mutex);
            // Increase validated files number
            sgx_thread_mutex_lock(&g_validated_files_num_mutex);
            g_validated_files_num++;
            sgx_thread_mutex_unlock(&g_validated_files_num_mutex);
            // Add file to deleted buffer
            sgx_thread_mutex_lock(&g_changed_files_v_mutex);
            g_changed_files_v.push_back(file);
            sgx_thread_mutex_unlock(&g_changed_files_v_mutex);
        }
    }

    // If report file flag is true, check if validating file is complete
    size_t wait_interval = 1000;
    size_t wait_time = 0;
    size_t timeout = (size_t)REPORT_SLOT * BLOCK_INTERVAL * 1000000;
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
            log_warn("Validate file timeout which will lead to generating work report failed! Please check your hardware.\n");
            break;
        }
    }

    // Change file status
    sgx_thread_mutex_lock(&g_changed_files_v_mutex);
    std::vector<json::JSON *> tmp_changed_files_v;
    tmp_changed_files_v.insert(tmp_changed_files_v.begin(), g_changed_files_v.begin(), g_changed_files_v.end());
    g_changed_files_v.clear();
    sgx_thread_mutex_unlock(&g_changed_files_v_mutex);
    if (tmp_changed_files_v.size() > 0)
    {
        SafeLock sl(wl->file_mutex);
        sl.lock();
        for (auto file : tmp_changed_files_v)
        {
            std::string cid = (*file)[FILE_CID].ToString();
            size_t index = 0;
            if(wl->is_file_dup_nolock(cid, index))
            {
                long cur_block_num = wl->sealed_files[index][CHAIN_BLOCK_NUMBER].ToInt();
                long val_block_num = g_validate_files_m[cid][CHAIN_BLOCK_NUMBER].ToInt();
                // We can get original file and new sealed file(this situation maybe exist)
                // If these two files are not the same one, cannot delete the file
                if (cur_block_num == val_block_num)
                {
                    char old_status = (*file)[FILE_STATUS].get_char(CURRENT_STATUS);
                    char new_status = old_status;
                    const char *old_status_ptr = NULL;
                    const char *new_status_ptr = NULL;
                    if (FILE_STATUS_VALID == old_status)
                    {
                        new_status = FILE_STATUS_LOST;
                        new_status_ptr = FILE_TYPE_LOST;
                        old_status_ptr = FILE_TYPE_VALID;
                    }
                    else if (FILE_STATUS_LOST == old_status)
                    {
                        new_status = FILE_STATUS_VALID;
                        new_status_ptr = FILE_TYPE_VALID;
                        old_status_ptr = FILE_TYPE_LOST;
                    }
                    else
                    {
                        continue;
                    }
                    log_info("File status changed, hash: %s status: %s -> %s\n",
                            cid.c_str(), file_status_2_name[old_status].c_str(), file_status_2_name[new_status].c_str());
                    // Change file status
                    wl->sealed_files[index][FILE_STATUS].set_char(CURRENT_STATUS, new_status);
                    if (FILE_STATUS_LOST == new_status)
                    {
                        wl->sealed_files[index][FILE_LOST_INDEX] = (*file)[FILE_LOST_INDEX];
                    }
                    else
                    {
                        wl->sealed_files[index][FILE_LOST_INDEX] = -1;
                    }
                    // Reduce valid file
                    wl->set_file_spec(new_status, g_validate_files_m[cid][FILE_SIZE].ToInt());
                    wl->set_file_spec(old_status, -g_validate_files_m[cid][FILE_SIZE].ToInt());
                    // Sync with APP sealed file info
                    ocall_change_file_type(cid.c_str(), old_status_ptr, new_status_ptr);
                }
            }
            else
            {
                log_err("Deal with bad file(%s) failed!\n", cid.c_str());
            }
        }
    }
}

/**
 * @description: Validate meaningful files real
 */
void validate_meaningful_file_real()
{
    Workload *wl = Workload::get_instance();

    // Get current validate random
    sgx_thread_mutex_lock(&g_validate_random_mutex);
    uint32_t cur_validate_random = g_validate_random;
    sgx_thread_mutex_unlock(&g_validate_random_mutex);

    // Get file info from iterator
    SafeLock sl_iter(g_validate_files_m_iter_mutex);
    sl_iter.lock();
    if (g_validate_files_m.size() == 0)
    {
        return;
    }
    std::string cid = g_validate_files_m_iter->first;
    json::JSON *file = const_cast<json::JSON *>(&g_validate_files_m_iter->second);
    g_validate_files_m_iter++;
    sl_iter.unlock();

    bool changed = false;
    bool lost = false;
    bool deleted = false;

    Defer finish_defer([&cur_validate_random, cid, &deleted, &changed, &file, &wl](void) {
        // Get current validate random
        sgx_thread_mutex_lock(&g_validate_random_mutex);
        uint32_t now_validate_random = g_validate_random;
        sgx_thread_mutex_unlock(&g_validate_random_mutex);
        // Check if validate random is the same
        if (cur_validate_random == now_validate_random)
        {
            // Increase validated files number
            sgx_thread_mutex_lock(&g_validated_files_num_mutex);
            g_validated_files_num++;
            sgx_thread_mutex_unlock(&g_validated_files_num_mutex);
            // Deal with result
            if (changed)
            {
                sgx_thread_mutex_lock(&g_changed_files_v_mutex);
                g_changed_files_v.push_back(file);
                sgx_thread_mutex_unlock(&g_changed_files_v_mutex);
            }
            if (deleted)
            {
                storage_delete_file(cid.c_str());
            }
        }
    });

    // If file status is not FILE_STATUS_VALID, return
    auto status = (*file)[FILE_STATUS];
    if (status.get_char(CURRENT_STATUS) == FILE_STATUS_PENDING
            || status.get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
    {
        return;
    }

    std::string root_cid = (*file)[FILE_CID].ToString();
    std::string root_hash = (*file)[FILE_HASH].ToString();
    size_t file_block_num = (*file)[FILE_BLOCK_NUM].ToInt();
    // Get tree string
    uint8_t *p_tree = NULL;
    size_t tree_sz = 0;
    crust_status_t crust_status = persist_get_unsafe(root_cid, &p_tree, &tree_sz);
    if (CRUST_SUCCESS != crust_status)
    {
        if (wl->is_in_deleted_file_buffer(root_cid))
        {
            return;
        }
        log_err("Validate meaningful data failed! Get tree:%s failed! Error code:%lx, will delete file.\n", root_cid.c_str(), crust_status);
        deleted = true;
        return;
    }
    Defer defer_tree([&p_tree](void) { free(p_tree); });
    // Validate merkle tree
    sgx_sha256_hash_t tree_hash;
    sgx_sha256_msg(p_tree, tree_sz, &tree_hash);
    if (memcmp((*file)[FILE_HASH].ToBytes(), &tree_hash, HASH_LENGTH) != 0)
    {
        log_err("File:%s merkle tree is not valid! Root hash doesn't equal!\n", root_cid.c_str());
        if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            lost = true;
        }
        return;
    }

    // ----- Validate file block ----- //
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
    // Validate lost data if have
    if (status.get_char(CURRENT_STATUS) == FILE_STATUS_LOST)
    {
        long lost_index = (*file)[FILE_LOST_INDEX].ToInt();
        if (lost_index >= 0 && lost_index < (*file)[FILE_BLOCK_NUM].ToInt())
        {
            block_idx_s.insert(lost_index);
        }
    }
    // Do check
    for (auto check_block_idx : block_idx_s)
    {
        // Get current node hash
        uint8_t *p_leaf = p_tree + check_block_idx * FILE_ITEM_LENGTH;
        std::string file_item = hexstring_safe(p_leaf, FILE_ITEM_LENGTH);
        std::string uuid = file_item.substr(0, UUID_LENGTH * 2);
        std::string leaf_hash = file_item.substr(UUID_LENGTH * 2, HASH_LENGTH * 2);
        // Compute current node hash by data
        uint8_t *p_sealed_data = NULL;
        size_t sealed_data_sz = 0;
        std::string leaf_path = uuid + root_cid + "/" + leaf_hash;
        crust_status = storage_get_file(leaf_path.c_str(), &p_sealed_data, &sealed_data_sz);
        if (CRUST_SUCCESS != crust_status)
        {
            if (wl->is_in_deleted_file_buffer(root_cid))
            {
                continue;
            }
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                log_err("Get file(%s) block:%ld failed!\n", leaf_path.c_str(), check_block_idx);
                (*file)[FILE_LOST_INDEX] = check_block_idx;
            }
            lost = true;
            continue;
        }
        Defer def_sealed_data([&p_sealed_data](void) { free(p_sealed_data); });
        // Validate sealed hash
        sgx_sha256_hash_t got_hash;
        sgx_sha256_msg(p_sealed_data, sealed_data_sz, &got_hash);
        if (memcmp(p_leaf + UUID_LENGTH, got_hash, HASH_LENGTH) != 0)
        {
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                log_err("File(%s) Index:%ld block hash is not expected!\n", root_cid.c_str(), check_block_idx);
                log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                log_err("Org hash : %s\n", leaf_hash.c_str());
                (*file)[FILE_LOST_INDEX] = check_block_idx;
            }
            lost = true;
            continue;
        }
    }
    if ((!lost && status.get_char(CURRENT_STATUS) == FILE_STATUS_LOST) 
            || (lost && status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID))
    {
        changed = true;
    }
}
