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
    crust_status_t crust_status = CRUST_SUCCESS;

    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&g_srd_mutex);

    size_t srd_num_threshold = 1 / SRD_VALIDATE_RATE * SRD_VALIDATE_MIN_NUM;
    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    size_t srd_validate_num = 0;
    size_t srd_punish_num = 0;
    size_t srd_validate_failed_num = 0;
    
    // Caculate srd validated variable
    if (srd_total_num >= srd_num_threshold)
    {
        srd_validate_num = srd_total_num * SRD_VALIDATE_RATE;
        srd_punish_num = 1 / SRD_VALIDATE_RATE;
    }
    else
    {
        if (srd_total_num < SRD_VALIDATE_MIN_NUM)
        {
            srd_validate_num = srd_total_num;
            srd_punish_num = 1;
        }
        else
        {
            srd_validate_num = SRD_VALIDATE_MIN_NUM;
            double tmp = (double)srd_total_num / (double)SRD_VALIDATE_MIN_NUM;
            srd_punish_num = tmp;
            if (tmp - (double)srd_punish_num > 0.0)
            {
                srd_punish_num++;
            }
        }
    }

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
        g_path = std::string(dir_path).append("/").append(unsigned_char_array_to_hex_string(p_g_hash, HASH_LENGTH));

        // Get M hashs
        ocall_get_file(&crust_status, get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
        if (m_hashs_org == NULL)
        {
            log_err("Get m hashs file failed in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        m_hashs = (uint8_t*)enc_malloc(m_hashs_size);
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
            log_err("Get leaf file failed in '%s'.\n", unsigned_char_array_to_hex_string(p_g_hash, HASH_LENGTH).c_str());
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
    srd_random_delete(srd_punish_num * srd_validate_failed_num, &del_path2idx_m);

    sgx_thread_mutex_unlock(&g_srd_mutex);
}

/**
 * @description: Validate Meaningful files
 */
void validate_meaningful_file()
{
    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Lock wl->checked_files
    sgx_thread_mutex_lock(&g_checked_files_mutex);

    // Add new file to validate
    sgx_thread_mutex_lock(&g_new_files_mutex);
    if (wl->new_files.size() > 0)
    {
        if (wl->checked_files.size() > 0)
        {
            // If file has been existed in checked_files, don't insert it into checked_files
            std::unordered_set<std::string> exist_s;
            for (int i = wl->checked_files.size() - 1, j = 0; i >= 0 && j < ENC_MAX_THREAD_NUM; i--, j++)
            {
                exist_s.insert(wl->checked_files[i][FILE_HASH].ToString());
            }
            // Judge if new file has been existed in checked_files
            for (int i = wl->new_files.size() - 1, j = 0; i >= 0 && j < ENC_MAX_THREAD_NUM; i--, j++)
            {
                if (exist_s.find(wl->new_files[i][FILE_HASH].ToString()) == exist_s.end())
                {
                    wl->checked_files.push_back(wl->new_files[i]);
                }
            }
        }
        else
        {
            // Insert new files to checked files
            wl->checked_files.insert(wl->checked_files.end(), wl->new_files.begin(), wl->new_files.end());
        }
        // Clear new files
        wl->new_files.clear();
    }
    sgx_thread_mutex_unlock(&g_new_files_mutex);

    // Initialize validatioin
    ocall_validate_init(&crust_status);
    if (CRUST_SUCCESS != crust_status)
    {
        wl->set_report_flag(false);
        ocall_validate_close();
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
        return;
    }

    // Get to be checked files indexes
    size_t check_file_num = wl->checked_files.size();
    if (wl->checked_files.size() > MEANINGFUL_VALIDATE_MIN_NUM)
    {
        check_file_num = wl->checked_files.size() * MEANINGFUL_VALIDATE_RATE;
    }
    std::vector<uint32_t> file_idx_v;
    uint32_t rand_val;
    size_t rand_index = 0;
    for (size_t i = 0; i < check_file_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        rand_index = rand_val % wl->checked_files.size();
        file_idx_v.push_back(rand_index);
    }

    // ----- Randomly check file block ----- //
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

        // If new file hasn't been confirmed, skip this validation
        if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_UNCONFIRMED) == 0)
        {
            continue;
        }

        std::string root_hash = wl->checked_files[file_idx][FILE_HASH].ToString();
        size_t file_block_num = wl->checked_files[file_idx][FILE_BLOCK_NUM].ToInt();
        // Get tree string
        crust_status = persist_get_unsafe(root_hash, &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status || 0 == data_len)
        {
            //log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_hash.c_str());
            if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) == 0)
            {
                wl->checked_files[file_idx][FILE_STATUS] = FILE_STATUS_LOST;
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }
        // Validate merkle tree
        std::string tree_str(reinterpret_cast<char *>(p_data), data_len);
        if (p_data != NULL)
        {
            free(p_data);
            p_data = NULL;
        }
        json::JSON tree_json = json::JSON::Load(tree_str);
        if (root_hash.compare(tree_json[FILE_HASH].ToString()) != 0 || CRUST_SUCCESS != validate_merkletree_json(tree_json))
        {
            log_err("File:%s merkle tree is not valid!\n", root_hash.c_str());
            if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) == 0)
            {
                wl->checked_files[file_idx][FILE_STATUS] = FILE_STATUS_LOST;
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }

        // ----- Validate MerkleTree ----- //
        // Note: should store serialized tree structure as "links_num":x,"hash":"xxxxx","size":
        // be careful about "links_num", "hash" and "size" sequence
        size_t spos, epos;
        spos = epos = 0;
        std::string stag = "\"" MT_LINKS_NUM "\":0,\"" MT_HASH "\":\"";
        std::string etag = "\",\"" MT_SIZE "\"";
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
        size_t cur_block_idx = 0;
        bool checked_ret = true;
        for (auto check_block_idx : block_idx_s)
        {
            // Get leaf node position
            do
            {
                spos = tree_str.find(stag, spos);
                if (spos == tree_str.npos)
                {
                    break;
                }
                spos += stag.size();
            } while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos || (epos = tree_str.find(etag, spos)) == tree_str.npos)
            {
                //log_err("Find leaf node failed!node index:%ld\n", check_block_idx);
                if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) == 0)
                {
                    wl->checked_files[file_idx][FILE_STATUS] = FILE_STATUS_LOST;
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                break;
            }
            // Get block data
            std::string leaf_hash = tree_str.substr(spos, epos - spos);
            std::string block_str = std::to_string(check_block_idx).append("_").append(leaf_hash);
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            ocall_validate_get_file(&crust_status, root_hash.c_str(), block_str.c_str(),
                                    &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                if (CRUST_VALIDATE_KARST_OFFLINE == crust_status)
                {
                    //log_err("Get file block:%ld failed!\n", check_block_idx);
                    wl->set_report_flag(false);
                    ocall_validate_close();
                    sgx_thread_mutex_unlock(&g_checked_files_mutex);
                    return;
                }
                if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) == 0)
                {
                    wl->checked_files[file_idx][FILE_STATUS] = FILE_STATUS_LOST;
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                break;
            }
            // Validate hash
            sgx_sha256_hash_t got_hash;
            sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
            uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
            if (leaf_hash_u == NULL)
            {
                log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
                continue;
            }
            if (memcmp(leaf_hash_u, got_hash, HASH_LENGTH) != 0)
            {
                //log_err("Index:%ld block hash is not expected!\n", check_block_idx);
                //log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                //log_err("Org hash : %s\n", leaf_hash.c_str());
                if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_VALID) == 0)
                {
                    wl->checked_files[file_idx][FILE_STATUS] = FILE_STATUS_LOST;
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
        // Set lost file back
        if (wl->checked_files[file_idx][FILE_STATUS].ToString().compare(FILE_STATUS_LOST) == 0 && checked_ret)
        {
            wl->checked_files[file_idx][FILE_STATUS] = FILE_STATUS_VALID;
            changed_idx2lost_um[file_idx] = false;
        }
    }

    // Change file status
    if (changed_idx2lost_um.size() > 0)
    {
        sgx_thread_mutex_lock(&g_metadata_mutex);
        json::JSON metadata_json;
        id_get_metadata(metadata_json, false);
        json::JSON meaningful_files_json = metadata_json[ID_FILE];
        for (auto it : changed_idx2lost_um)
        {
            if ((int)it.first < meaningful_files_json.size())
            {
                std::string org_status = meaningful_files_json[it.first][FILE_STATUS].ToString();
                meaningful_files_json[it.first][FILE_STATUS] = it.second ? FILE_STATUS_LOST : FILE_STATUS_VALID;
                log_info("File status changed, hash: %s status: %s -> %s\n",
                        meaningful_files_json[it.first][FILE_HASH].ToString().c_str(),
                        org_status.c_str(),
                        meaningful_files_json[it.first][FILE_STATUS].ToString().c_str());
            }
        }
        id_metadata_set_or_append(ID_FILE, meaningful_files_json, ID_UPDATE, false);
        sgx_thread_mutex_unlock(&g_metadata_mutex);
    }

    ocall_validate_close();

    // Unlock wl->checked_files
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}
