#include "Validator.h"
#include "Identity.h"
#include "Srd.h"
#include "EJson.h"
#include <algorithm>

extern sgx_thread_mutex_t g_srd_mutex;
extern sgx_thread_mutex_t g_checked_files_mutex;
extern sgx_thread_mutex_t g_new_files_mutex;

/**
 * @description: Randomly delete punish number of srd
 * @param punish_num -> To be deleted srd space for punishment
 * @param del_indexes -> Pointer to to be deleted srd path to hash map
 */
void srd_random_delete(long punish_num, std::map<std::string, std::set<size_t>> *del_indexes)
{
    if (punish_num <= 0 && del_indexes->size() == 0)
    {
        return;
    }

    log_info("Check srd failed! %ldG space will be deleted for punishment!\n", punish_num);

    srd_decrease(punish_num, del_indexes);
}

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

    sgx_thread_mutex_lock(&g_srd_mutex);

    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    size_t srd_validate_num = std::max((size_t)(srd_total_num * SRD_VALIDATE_RATE), (size_t)SRD_VALIDATE_MIN_NUM);
    srd_validate_num = std::min(srd_validate_num, srd_total_num);
    size_t srd_validate_failed_num = 0;
    
    // Randomly choose validate srd files
    std::set<std::pair<uint32_t, uint32_t>> validate_srd_idx_s;
    std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry;
    if (srd_validate_num < srd_total_num)
    {
        uint32_t rand_val;
        uint32_t rand_idx = 0;
        std::pair<uint32_t, uint32_t> p_chose;
        for (size_t i = 0; i < srd_validate_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            chose_entry = wl->srd_path2hashs_m.begin();
            uint32_t path_idx = rand_val % wl->srd_path2hashs_m.size();
            for (uint32_t i = 0; i < path_idx; i++)
            {
                chose_entry++;
            }
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_idx = rand_val % chose_entry->second.size();
            p_chose = std::make_pair(path_idx, rand_idx);
            validate_srd_idx_s.insert(p_chose);
        }
    }
    else
    {
        int i = 0;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++, i++)
        {
            for (size_t j = 0; j < it->second.size(); j++)
            {
                validate_srd_idx_s.insert(make_pair(i, j));
            }
        }
    }

    // ----- Validate SRD ----- //
    std::map<std::string, std::set<size_t>> del_path2idx_m;
    for (auto srd_idx : validate_srd_idx_s)
    {
        // Check sched func
        sched_check(SCHED_VALIDATE_SRD, g_srd_mutex);
        // If srd has been deleted, go to next check
        std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry = wl->srd_path2hashs_m.begin();
        for (size_t i = 0; i < srd_idx.first && chose_entry != wl->srd_path2hashs_m.end(); i++)
        {
            chose_entry++;
        }
        if (chose_entry == wl->srd_path2hashs_m.end() || srd_idx.second >= chose_entry->second.size())
        {
            continue;
        }

        uint8_t *m_hashs_org = NULL;
        uint8_t *m_hashs = NULL;
        size_t m_hashs_size = 0;
        sgx_sha256_hash_t m_hashs_sha256;
        size_t srd_block_index = 0;
        std::string leaf_path;
        uint8_t *leaf_data = NULL;
        size_t leaf_data_len = 0;
        sgx_sha256_hash_t leaf_hash;
        std::string hex_g_hash;
        std::string dir_path;
        std::string g_path;

        dir_path = chose_entry->first;
        uint8_t *p_g_hash = chose_entry->second[srd_idx.second];

        // Get g_hash corresponding path
        hex_g_hash = hexstring_safe(p_g_hash, HASH_LENGTH);
        g_path = std::string(dir_path).append("/").append(hexstring_safe(p_g_hash, HASH_LENGTH));

        // Get M hashs
        ocall_get_file(&crust_status, get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
        if (m_hashs_org == NULL)
        {
            log_err("Get m hashs file failed in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        m_hashs = (uint8_t *)enc_malloc(m_hashs_size);
        if (m_hashs == NULL)
        {
            log_err("Malloc memory failed!\n");
            goto nextloop;
        }
        memset(m_hashs, 0, m_hashs_size);
        memcpy(m_hashs, m_hashs_org, m_hashs_size);

        // Compare M hashs
        sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_sha256);
        if (memcmp(p_g_hash, m_hashs_sha256, HASH_LENGTH) != 0)
        {
            log_err("Wrong m hashs file in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        // Get leaf data
        uint32_t rand_val;
        sgx_read_rand((uint8_t*)&rand_val, 4);
        srd_block_index = rand_val % SRD_RAND_DATA_NUM;
        leaf_path = get_leaf_path(g_path.c_str(), srd_block_index, m_hashs + srd_block_index * 32);
        ocall_get_file(&crust_status, leaf_path.c_str(), &leaf_data, &leaf_data_len);

        if (leaf_data == NULL)
        {
            log_err("Get leaf file failed in '%s'.\n", hexstring_safe(p_g_hash, HASH_LENGTH).c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        // Compare leaf data
        sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_hash);
        if (memcmp(m_hashs + srd_block_index * 32, leaf_hash, HASH_LENGTH) != 0)
        {
            log_err("Wrong leaf data hash in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }


    nextloop:
        if (m_hashs != NULL)
        {
            free(m_hashs);
        }
    }

    // Delete indicated punished files
    for (auto it : del_path2idx_m)
    {
        srd_validate_failed_num += it.second.size();
    }
    srd_random_delete(SRD_PUNISH_FACTOR * srd_validate_failed_num, &del_path2idx_m);

    sgx_thread_mutex_unlock(&g_srd_mutex);
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

    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Lock wl->checked_files
    SafeLock cf_lock(g_checked_files_mutex);
    cf_lock.lock();

    // Add new file to validate
    sgx_thread_mutex_lock(&g_new_files_mutex);
    if (wl->new_files.size() > 0)
    {
        // Insert new files to checked files
        for (auto fj : wl->new_files)
        {
            fj[FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_VALID);
            wl->checked_files.push_back(fj);
        }
        // Clear new files
        wl->new_files.clear();
    }
    sgx_thread_mutex_unlock(&g_new_files_mutex);

    // Get to be checked files indexes
    size_t check_file_num = std::max((size_t)(wl->checked_files.size() * MEANINGFUL_VALIDATE_RATE), (size_t)MEANINGFUL_VALIDATE_MIN_NUM);
    check_file_num = std::min(check_file_num, wl->checked_files.size());
    std::vector<uint32_t> file_idx_v;
    uint32_t rand_val;
    size_t rand_index = 0;
    for (size_t i = 0; i < check_file_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        rand_index = rand_val % wl->checked_files.size();
        file_idx_v.push_back(rand_index);
    }

    // ----- Validate file ----- //
    // TODO: Do we allow to store duplicated files?
    // Used to indicate which meaningful file status has been changed
    std::unordered_map<size_t, bool> changed_idx2lost_um;
    for (auto file_idx : file_idx_v)
    {
        // Check race
        sched_check(SCHED_VALIDATE_FILE, g_checked_files_mutex);
        // If file has been deleted, go to next check
        if (file_idx >= wl->checked_files.size())
        {
            continue;
        }

        // If new file hasn't been verified, skip this validation
        auto status = &wl->checked_files[file_idx][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
        {
            continue;
        }

        std::string root_cid = wl->checked_files[file_idx][FILE_CID].ToString();
        std::string root_hash = wl->checked_files[file_idx][FILE_HASH].ToString();
        size_t file_block_num = wl->checked_files[file_idx][FILE_BLOCK_NUM].ToInt();
        // Get tree string
        crust_status = persist_get_unsafe(root_cid, &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status)
        {
            log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_cid.c_str());
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                changed_idx2lost_um[file_idx] = true;
            }
            if (p_data != NULL)
            {
                free(p_data);
                p_data = NULL;
            }
            continue;
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
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }

        // ----- Validate MerkleTree ----- //
        // Get to be checked block index
        std::set<size_t> block_idx_s;
        for (size_t i = 0; i < MEANINGFUL_VALIDATE_MIN_BLOCK_NUM && i < file_block_num; i++)
        {
            size_t tmp_idx = 0;
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
        size_t spos, epos;
        spos = epos = 0;
        std::string cid_tag(MT_CID "\":\"");
        std::string dhash_tag(MT_DATA_HASH "\":\"");
        size_t cur_block_idx = 0;
        for (auto check_block_idx : block_idx_s)
        {
            // Get leaf node position
            do
            {
                spos = tree_str.find(cid_tag, spos);
                if (spos == tree_str.npos)
                {
                    break;
                }
                spos += cid_tag.size();
            } while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos)
            {
                log_err("Find file(%s) leaf node cid failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                    changed_idx2lost_um[file_idx] = true;
                }
                break;
            }
            // Get current node cid
            std::string cur_cid = tree_str.substr(spos, CID_LENGTH);
            // Get current node hash
            epos = tree_str.find(dhash_tag, spos);
            if (epos == tree_str.npos)
            {
                log_err("Find file(%s) leaf node hash failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                    changed_idx2lost_um[file_idx] = true;
                }
                break;
            }
            epos += dhash_tag.size();
            std::string leaf_hash = tree_str.substr(epos, HASH_LENGTH * 2);
            // Compute current node hash by data
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            crust_status = storage_ipfs_cat(cur_cid.c_str(), &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                if (p_sealed_data != NULL)
                {
                    free(p_sealed_data);
                }
                if (CRUST_SERVICE_UNAVAILABLE == crust_status)
                {
                    log_err("IPFS is offline!Please start it!\n");
                    wl->set_report_file_flag(false);
                    return;
                }
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                    changed_idx2lost_um[file_idx] = true;
                }
                log_err("Get file(%s) block:%ld failed!\n", root_cid.c_str(), check_block_idx);
                break;
            }
            // Validate hash
            sgx_sha256_hash_t got_hash;
            sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
            if (p_sealed_data != NULL)
            {
                free(p_sealed_data);
            }
            uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
            if (leaf_hash_u == NULL)
            {
                log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
                continue;
            }
            if (memcmp(leaf_hash_u, got_hash, HASH_LENGTH) != 0)
            {
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    log_err("File(%s) Index:%ld block hash is not expected!\n", root_cid.c_str(), check_block_idx);
                    log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                    log_err("Org hash : %s\n", leaf_hash.c_str());
                    status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                    changed_idx2lost_um[file_idx] = true;
                }
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
    }

    // Change file status
    if (changed_idx2lost_um.size() > 0)
    {
        for (auto it : changed_idx2lost_um)
        {
            log_info("File status changed, hash: %s status: valid -> lost, will be deleted\n",
                    wl->checked_files[it.first][FILE_CID].ToString().c_str());
            std::string cid = wl->checked_files[it.first][FILE_CID].ToString();
            // Delete real file
            ocall_ipfs_del(&crust_status, cid.c_str());
            // Delete file tree structure
            persist_del(cid);
            // Reduce valid file
            wl->set_wl_spec(FILE_STATUS_VALID, wl->checked_files[it.first][FILE_OLD_SIZE].ToInt());
        }
    }
}
