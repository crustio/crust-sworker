#include "Validator.h"
#include "Identity.h"
#include "EJson.h"

extern sgx_thread_mutex_t g_workload_mutex;

// For timeout
long long g_validate_timeout = 0;

/**
 * @description: validate empty disk
 * @param path -> the empty disk path
 */
void validate_empty_disk(const char *path)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *p_workload = Workload::get_instance();

    for (auto it_g_hash = p_workload->empty_g_hashs.begin(); it_g_hash != p_workload->empty_g_hashs.end(); it_g_hash++)
    {
        // Base info
        unsigned char *g_hash = (unsigned char *)malloc(HASH_LENGTH);
        std::string g_path;

        // For checking M hashs
        unsigned char *m_hashs_o = NULL;
        size_t m_hashs_size = 0;
        unsigned char *m_hashs = NULL;
        sgx_sha256_hash_t m_hashs_hash256;

        // For checking leaf
        unsigned int rand_val_m;
        size_t select = 0;
        std::string leaf_path;
        unsigned char *leaf_data = NULL;
        size_t leaf_data_len = 0;
        sgx_sha256_hash_t leaf_data_hash256;

        // Get g hash
        sgx_thread_mutex_lock(&g_workload_mutex);
        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            g_hash[j] = (*it_g_hash)[j];
        }
        sgx_thread_mutex_unlock(&g_workload_mutex);

        if (is_null_hash(g_hash))
        {
            goto end_validate_one_g_empty;
        }
        g_path = get_g_path_with_hash(path, g_hash);

        // Get M hashs
        ocall_get_file(&crust_status, get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_o, &m_hashs_size);
        if (m_hashs_o == NULL)
        {
            log_warn("Get m hashs file failed in '%s'.\n", unsigned_char_array_to_hex_string(g_hash, HASH_LENGTH).c_str());
            goto end_validate_one_g_empty_failed;
        }

        m_hashs = new unsigned char[m_hashs_size];
        for (size_t j = 0; j < m_hashs_size; j++)
        {
            m_hashs[j] = m_hashs_o[j];
        }

        /* Compare M hashs */
        sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_hash256);
        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            if (g_hash[j] != m_hashs_hash256[j])
            {
                log_warn("Wrong m hashs file in '%s'.\n", unsigned_char_array_to_hex_string(g_hash, HASH_LENGTH).c_str());
                goto end_validate_one_g_empty_failed;
            }
        }

        /* Get leaf data */
        sgx_read_rand((unsigned char *)&rand_val_m, 4);
        select = rand_val_m % SRD_RAND_DATA_NUM;
        leaf_path = get_leaf_path(g_path.c_str(), select, m_hashs + select * 32);
        ocall_get_file(&crust_status, leaf_path.c_str(), &leaf_data, &leaf_data_len);

        if (leaf_data == NULL)
        {
            log_warn("Get leaf file failed in '%s'.\n", unsigned_char_array_to_hex_string(g_hash, HASH_LENGTH).c_str());
            goto end_validate_one_g_empty_failed;
        }

        /* Compare leaf data */
        sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_data_hash256);

        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            if (m_hashs[select * 32 + j] != leaf_data_hash256[j])
            {
                log_warn("Wrong leaf data hash in '%s'.\n", unsigned_char_array_to_hex_string(g_hash, HASH_LENGTH).c_str());
                goto end_validate_one_g_empty_failed;
            }
        }

    goto end_validate_one_g_empty;
    end_validate_one_g_empty_failed:
        sgx_thread_mutex_lock(&g_workload_mutex);
        ocall_delete_folder_or_file(&crust_status, g_path.c_str());
        free(*it_g_hash);
        it_g_hash = p_workload->empty_g_hashs.erase(it_g_hash);
        it_g_hash--;
        sgx_thread_mutex_unlock(&g_workload_mutex);
        
    end_validate_one_g_empty:
        if (g_hash != NULL)
        {
            free(g_hash);
        }
        if (m_hashs != NULL)
        {
            delete[] m_hashs;
        }
    }
}

/**
 * @description: get all links' hash from block
 * @param block_data -> the block data
 * @param block_size -> the size of block data
 */
std::vector<std::string> get_hashs_from_block(unsigned char *block_data, size_t block_size)
{
    std::vector<std::string> hashs;
    if (block_data == NULL)
    {
        return hashs;
    }

    std::string block_data_str = unsigned_char_array_to_hex_string(block_data, block_size);

    std::string flag = "0a221220";
    size_t position = 0;

    while ((position = block_data_str.find(flag, position)) != std::string::npos)
    {
        hashs.push_back(block_data_str.substr(position + flag.length(), HASH_LENGTH * 2));
        position += flag.length() + HASH_LENGTH * 2;
    }

    return hashs;
}

/**
 * @description: Validate Meaningful files
 * */
void validate_meaningful_file()
{
    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Initialize validatioin
    ocall_validate_init(&crust_status);
    if (CRUST_SUCCESS != crust_status)
    {
        wl->files_json = json::Array();
        ocall_validate_close();
        return;
    }

    // Get to be checked files indexes
    size_t check_file_num = wl->files_json.length();
    if (wl->files_json.length() > MIN_VALIDATE_FILE_NUM)
    {
        check_file_num = wl->files_json.length() * MEANINGFUL_FILE_VALIDATE_RATE;
    }
    std::set<uint32_t> file_idx_s;
    uint32_t rand_val;
    size_t rand_index = 0;
    log_debug("check file num:%ld\n", check_file_num);
    while (file_idx_s.size() < check_file_num)
    {
        do
        {
            sgx_read_rand((uint8_t *)&rand_val, 1);
            rand_index = rand_val % wl->files_json.length();
        } 
        while (file_idx_s.find(rand_index) != file_idx_s.end());
        file_idx_s.insert(rand_index);
    }

    // ----- Randomly check file block ----- //
    // TODO: Do we allow store duplicated files?
    std::vector<int> exist_indexes(wl->files_json.size(), 1);
    int exist_acc = wl->files_json.size();
    for (auto file_idx : file_idx_s)
    {
        std::string root_hash = wl->files_json[file_idx]["hash"].ToString();
        size_t file_block_num = wl->files_json[file_idx]["size"].ToInt();
        file_block_num = file_block_num / MAX_BLOCK_SIZE;
        log_debug("Validating file root hash:%s\n", root_hash.c_str());
        // Get tree string
        crust_status = persist_get(root_hash.c_str(), &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status || 0 == data_len)
        {
            log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_hash.c_str());
            exist_indexes[file_idx] = 0;
            exist_acc--;
            continue;
        }
        std::string tree_str(reinterpret_cast<char *>(p_data), data_len);
        free(p_data);
        // Validate MerkleTree
        size_t spos, epos;
        spos = epos = 0;
        std::string stag = "\"links_num\":0,\"hash\":\"";
        std::string etag = "\",\"size\"";
        // Get to be checked block index
        std::set<size_t> block_idx_s;
        while (block_idx_s.size() < MAX_VALIDATE_BLOCK_NUM && block_idx_s.size() < file_block_num)
        {
            size_t tmp_idx = 0;
            do
            {
                sgx_read_rand((uint8_t *)&rand_val, 4);
                tmp_idx = rand_val % file_block_num;
            }
            while (block_idx_s.find(tmp_idx) != block_idx_s.end());
            block_idx_s.insert(tmp_idx);
        }
        // Do check
        size_t cur_block_idx = 0;
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
            }
            while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos || (epos = tree_str.find(etag, spos)) == tree_str.npos)
            {
                log_err("Find leaf node failed!node index:%ld\n", check_block_idx);
                exist_indexes[file_idx] = 0;
                exist_acc--;
                break;
            }
            // Get block data
            std::string leaf_hash = tree_str.substr(spos, epos - spos);
            std::string block_str = std::to_string(check_block_idx).append("_").append(leaf_hash);
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            log_debug("Checking block hash:%ld_%s\n", check_block_idx, leaf_hash.c_str());
            ocall_validate_get_file(&crust_status, root_hash.c_str(), block_str.c_str(),
                    &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                log_err("Get file block:%ld failed!\n", check_block_idx);
                exist_indexes[file_idx] = 0;
                exist_acc--;
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
                log_err("Index:%ld block hash is not expected!\n", check_block_idx);
                log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                log_err("Org hash : %s\n", leaf_hash.c_str());
                exist_indexes[file_idx] = 0;
                exist_acc--;
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
    }

    // Delete not exists json
    if (exist_acc != wl->files_json.size())
    {
        json::JSON new_files_json = json::Array();
        for (size_t i = 0,j = 0; i < exist_indexes.size(); i++)
        {
            if (exist_indexes[i] == 1)
            {
                new_files_json[j] = wl->files_json[i];
                j++;
            }
        }
        wl->files_json = new_files_json;
    }

    ocall_validate_close();
}
