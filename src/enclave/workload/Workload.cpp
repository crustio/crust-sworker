#include "Workload.h"

sgx_thread_mutex_t g_workload_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_report_flag_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_upgrade_status_mutex = SGX_THREAD_MUTEX_INITIALIZER;

Workload *Workload::workload = NULL;

/**
 * @desination: Single instance class function to get instance
 * @return: Workload instance
 */
Workload *Workload::get_instance()
{
    if (Workload::workload == NULL)
    {
        sgx_thread_mutex_lock(&g_workload_mutex);
        if (Workload::workload == NULL)
        {
            Workload::workload = new Workload();
        }
        sgx_thread_mutex_unlock(&g_workload_mutex);
    }

    return Workload::workload;
}

/**
 * @description: Initialize workload
 */
Workload::Workload()
{
    this->report_files = true;
    this->wl_spec_info[g_file_status[FILE_STATUS_VALID]]["num"] = 0;
    this->wl_spec_info[g_file_status[FILE_STATUS_VALID]]["size"] = 0;
}

/**
 * @description: Destructor
 */
Workload::~Workload()
{
    for (auto it : this->srd_path2hashs_m)
    {
        for (auto g_hash : it.second)
        {
            if (g_hash != NULL)
                free(g_hash);
        }
    }
    this->srd_path2hashs_m.clear();
}

/**
 * @description: Print work report
 * @return: Generated workload
 */
std::string Workload::get_workload(void)
{
    json::JSON wl_json;

    // File info
    sgx_thread_mutex_lock(&wl_spec_info_mutex);
    wl_json[WL_FILES] = this->wl_spec_info;
    sgx_thread_mutex_unlock(&wl_spec_info_mutex);
    // Srd info
    wl_json[WL_SRD][WL_SRD_DETAIL] = this->get_srd_info();
    wl_json[WL_SRD][WL_SRD_REMAINING_TASK] = get_srd_task();

    std::string wl_str = wl_json.dump();
    remove_char(wl_str, '\n');
    remove_char(wl_str, '\\');
    remove_char(wl_str, ' ');
    ocall_store_workload(wl_str.c_str(), wl_str.size(), true);

    return wl_str;
}

/**
 * @description: Clean up work report data
 */
void Workload::clean_srd_buffer()
{
    // Clean srd_path2hashs_m
    for (auto it : this->srd_path2hashs_m)
    {
        for (auto g_hash : it.second)
        {
            if (g_hash != NULL)
                free(g_hash);
        }
    }
    this->srd_path2hashs_m.clear();
}

/**
 * @description: Generate workload info
 * @return: Workload info in json format
 */
json::JSON Workload::gen_workload_info()
{
    // Generate srd information
    long g_num = 0;
    sgx_sha256_hash_t srd_root;
    json::JSON ans;
    if (this->srd_path2hashs_m.size() == 0)
    {
        memset(&srd_root, 0, sizeof(sgx_sha256_hash_t));
        ans[WL_SRD_ROOT_HASH] = reinterpret_cast<uint8_t *>(&srd_root);
    }
    else
    {
        for (auto it : this->srd_path2hashs_m)
        {
            g_num += it.second.size();
        }
        uint8_t *g_hashs = (uint8_t *)enc_malloc(g_num * HASH_LENGTH);
        if (g_hashs == NULL)
        {
            return ans;
        }
        memset(g_hashs, 0, g_num * HASH_LENGTH);
        size_t g_hashs_len = 0;
        for (auto it : this->srd_path2hashs_m)
        {
            for (auto g_hash : it.second)
            {
                memcpy(g_hashs + g_hashs_len, g_hash, HASH_LENGTH);
                g_hashs_len += HASH_LENGTH;
            }
        }
        ans[WL_SRD_SPACE] = g_num * 1024 * 1024 * 1024;
        sgx_sha256_msg(g_hashs, (uint32_t)g_hashs_len, &srd_root);
        free(g_hashs);
        ans[WL_SRD_ROOT_HASH] = reinterpret_cast<uint8_t *>(&srd_root);
    }

    // Generate file information
    sgx_sha256_hash_t file_root;
    if (this->sealed_files.size() == 0)
    {
        memset(&file_root, 0, sizeof(sgx_sha256_hash_t));
        ans[WL_FILE_ROOT_HASH] = reinterpret_cast<uint8_t *>(&file_root);
    }
    else
    {
        uint8_t *f_hashs = (uint8_t *)enc_malloc(this->sealed_files.size() * HASH_LENGTH);
        memset(f_hashs, 0, this->sealed_files.size() * HASH_LENGTH);
        size_t f_hashs_len = 0;
        for (size_t i = 0; i < this->sealed_files.size(); i++)
        {
            memcpy(f_hashs + f_hashs_len, this->sealed_files[i][FILE_HASH].ToBytes(), HASH_LENGTH);
            f_hashs_len += HASH_LENGTH;
        }
        sgx_sha256_msg(f_hashs, (uint32_t)f_hashs_len, &file_root);
        free(f_hashs);
        ans[WL_FILE_ROOT_HASH] = reinterpret_cast<uint8_t *>(&file_root);
    }

    return ans;
}

/**
 * @description: Serialize workload for sealing
 * @param sered_srd -> Reference to serialized srd
 * @return: Serialized workload
 */
crust_status_t Workload::serialize_srd(uint8_t **p_data, size_t *data_size)
{
    SafeLock sl(this->srd_mutex);
    sl.lock();
    
    // Calculate srd space
    size_t srd_size = id_get_srd_buffer_size(this->srd_path2hashs_m);
    uint8_t *srd_buffer = (uint8_t *)enc_malloc(srd_size);
    if (srd_buffer == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(srd_buffer, 0, srd_size);

    // Copy srd information to buffer
    size_t i = 0;
    size_t srd_offset = 0;
    memcpy(srd_buffer, "{", 1);
    srd_offset += 1;
    for (auto it = this->srd_path2hashs_m.begin(); it != this->srd_path2hashs_m.end(); it++, i++)
    {
        std::string tmp1 = "\"" + it->first + "\":[";
        memcpy(srd_buffer + srd_offset, tmp1.c_str(), tmp1.size());
        srd_offset += tmp1.size();
        for (size_t j = 0; j < it->second.size(); j++)
        {
            std::string tmp2 = "\"" + hexstring_safe(it->second[j], HASH_LENGTH) + "\"";
            if (j != it->second.size() - 1)
            {
                tmp2.append(",");
            }
            memcpy(srd_buffer + srd_offset, tmp2.c_str(), tmp2.size());
            srd_offset += tmp2.size();
        }
        std::string tmp3("]");
        if (i != this->srd_path2hashs_m.size() - 1)
        {
            tmp3.append(",");
        }
        memcpy(srd_buffer + srd_offset, tmp3.c_str(), tmp3.size());
        srd_offset += tmp3.size();
    }
    memcpy(srd_buffer + srd_offset, "}", 1);
    srd_offset += 1;
    
    *p_data = srd_buffer;
    *data_size = srd_offset;

    sl.unlock();

    return CRUST_SUCCESS;
}

/**
 * @description: Serialize file for sealing
 * @param p_data -> Pointer to point to data
 * @param data_size -> Serialized data size
 * @return: Serialized result
 */
crust_status_t Workload::serialize_file(uint8_t **p_data, size_t *data_size)
{
    sgx_thread_mutex_lock(&this->file_mutex);

    size_t buffer_size = id_get_file_buffer_size(this->sealed_files);
    *p_data = (uint8_t *)enc_malloc(buffer_size);
    if (*p_data == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(*p_data, 0, buffer_size);
    size_t offset = 0;

    memcpy(*p_data + offset, "[", 1);
    offset += 1;
    for (size_t i = 0; i < this->sealed_files.size(); i++)
    {
        std::string file_str = this->sealed_files[i].dump();
        remove_char(file_str, '\n');
        remove_char(file_str, '\\');
        remove_char(file_str, ' ');
        if (i != this->sealed_files.size() - 1)
        {
            file_str.append(",");
        }
        memcpy(*p_data + offset, file_str.c_str(), file_str.size());
        offset += file_str.size();
    }
    memcpy(*p_data + offset, "]", 1);
    offset += 1;

    *data_size = offset;

    sgx_thread_mutex_unlock(&this->file_mutex);

    return CRUST_SUCCESS;
}

/**
 * @description: Restore workload from serialized workload
 * @param g_hashs -> G hashs json data
 * @return: Restore status
 */
crust_status_t Workload::restore_srd(json::JSON g_hashs)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    // Clean srd_path2hashs_m
    for (auto it : this->srd_path2hashs_m)
    {
        for (auto g_hash : it.second)
        {
            if (g_hash != NULL)
                free(g_hash);
        }
    }
    this->srd_path2hashs_m.clear(); // Clear current srd_path2hashs_m
    // Restore g_hashs
    auto p_obj = g_hashs.ObjectRange();
    for (auto it = p_obj.begin(); it != p_obj.end(); it++)
    {
        for (int i = 0; i < it->second.size(); i++)
        {
            std::string hex_g_hash = it->second[i].ToString();
            uint8_t *g_hash = hex_string_to_bytes(hex_g_hash.c_str(), hex_g_hash.size());
            if (g_hash == NULL)
            {
                clean_srd_buffer();
                return CRUST_UNEXPECTED_ERROR;
            }
            this->srd_path2hashs_m[it->first].push_back(g_hash);
        }
    }
    // Restore srd info
    for (auto it : this->srd_path2hashs_m)
    {
        if (0 != it.second.size())
        {
            this->srd_info_json[it.first]["assigned"] = it.second.size();
        }
    }

    return crust_status;
}

/**
 * @description: Restore file from json
 * @param file_json -> File json
 */
void Workload::restore_file(json::JSON file_json)
{
    this->sealed_files.clear();
    for (int i = 0; i < file_json.size(); i++)
    {
        this->sealed_files.push_back(file_json[i]);
        // Restore workload spec info
        set_wl_spec(file_json[i][FILE_STATUS].get_char(CURRENT_STATUS), file_json[i][FILE_SIZE].ToInt());
    }
}

/**
 * @description: Set report file flag
 * @param flag -> Report flag
 */
void Workload::set_report_file_flag(bool flag)
{
    sgx_thread_mutex_lock(&g_report_flag_mutex);
    this->report_files = flag;
    sgx_thread_mutex_unlock(&g_report_flag_mutex);
}

/**
 * @description: Get report flag
 * @return: Report flag
 */
bool Workload::get_report_file_flag()
{
    sgx_thread_mutex_lock(&g_report_flag_mutex);
    bool flag = this->report_files;
    sgx_thread_mutex_unlock(&g_report_flag_mutex);
    return flag;
}

/**
 * @description: Set srd info
 * @param path -> Changed path
 * @param change -> Change number
 */
void Workload::set_srd_info(std::string path, long change)
{
    sgx_thread_mutex_lock(&this->srd_info_mutex);
    this->srd_info_json[path]["assigned"] = this->srd_info_json[path]["assigned"].ToInt() + change;
    if (this->srd_info_json[path]["assigned"].ToInt() <= 0)
    {
        this->srd_info_json.ObjectRange().object->erase(path);
    }
    sgx_thread_mutex_unlock(&this->srd_info_mutex);
}

/**
 * @description: Get srd info
 * @return: Return srd info json
 */
json::JSON Workload::get_srd_info()
{
    sgx_thread_mutex_lock(&this->srd_info_mutex);
    if (this->srd_info_json.size() <= 0)
    {
        this->srd_info_json = json::JSON();
    }
    json::JSON srd_info = this->srd_info_json;
    sgx_thread_mutex_unlock(&this->srd_info_mutex);

    return srd_info;
}

/**
 * @description: Set upgrade flag
 * @param pub_key -> Previous version's public key
 */
void Workload::set_upgrade(sgx_ec256_public_t pub_key)
{
    this->upgrade = true;
    memcpy(&this->pre_pub_key, &pub_key, sizeof(sgx_ec256_public_t));
}

/**
 * @description: Get upgrade flag
 * @return: Upgrade flag
 */
bool Workload::is_upgrade()
{
    return this->upgrade;
}

/**
 * @description: Set is_upgrading flag
 * @param status -> Enclave upgrade status
 */
void Workload::set_upgrade_status(enc_upgrade_status_t status)
{
    sgx_thread_mutex_lock(&g_upgrade_status_mutex);
    this->upgrade_status = status;
    switch (status)
    {
        case ENC_UPGRADE_STATUS_NONE:
            log_debug("Set upgrade status:ENC_UPGRADE_STATUS_NONE\n");
            break;
        case ENC_UPGRADE_STATUS_PROCESS:
            log_debug("Set upgrade status:ENC_UPGRADE_STATUS_PROCESS\n");
            break;
        case ENC_UPGRADE_STATUS_SUCCESS:
            log_debug("Set upgrade status:ENC_UPGRADE_STATUS_SUCCESS\n");
            break;
        default:
            log_debug("Unknown upgrade status!\n");
    }
    sgx_thread_mutex_unlock(&g_upgrade_status_mutex);
}

/**
 * @description: Get is_upgrading flag
 * @return: Enclave upgrade status
 * */
enc_upgrade_status_t Workload::get_upgrade_status()
{
    enc_upgrade_status_t status = ENC_UPGRADE_STATUS_NONE;
    sgx_thread_mutex_lock(&g_upgrade_status_mutex);
    status = this->upgrade_status;
    sgx_thread_mutex_unlock(&g_upgrade_status_mutex);
    return status;
}

/**
 * @description: Handle workreport result
 */
void Workload::handle_report_result()
{
    // Set file status by report result
    sgx_thread_mutex_lock(&this->file_mutex);
    for (auto i : this->reported_files_idx)
    {
        if (i < this->sealed_files.size())
        {
            auto status = &this->sealed_files[i][FILE_STATUS];
            status->set_char(ORIGIN_STATUS, status->get_char(WAITING_STATUS));
        }
    }
    this->reported_files_idx.clear();
    sgx_thread_mutex_unlock(&this->file_mutex);
}

/**
 * @description: Check if can report workreport
 * @param block_height -> Block height
 * @return: Check status
 */
crust_status_t Workload::try_report_work(size_t block_height)
{
    if (block_height == 0 || block_height - this->get_report_height() - WORKREPORT_REPORT_INTERVAL < ERA_LENGTH)
    {
        return CRUST_UPGRADE_BLOCK_EXPIRE;
    }

    if (!this->report_has_validated_proof())
    {
        return CRUST_UPGRADE_NO_VALIDATE;
    }

    if (this->get_restart_flag())
    {
        return CRUST_UPGRADE_RESTART;
    }

    if (!this->get_report_file_flag())
    {
        return CRUST_UPGRADE_NO_FILE;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Set workload spec information
 * @param file_status -> Workload spec
 * @param change -> Spec information change
 */
void Workload::set_wl_spec(char file_status, long long change)
{
    if (g_file_status.find(file_status) != g_file_status.end())
    {
        sgx_thread_mutex_lock(&wl_spec_info_mutex);
        std::string ws_name = g_file_status[file_status];
        this->wl_spec_info[ws_name]["num"] = this->wl_spec_info[ws_name]["num"].ToInt() + (change > 0 ? 1 : -1);
        this->wl_spec_info[ws_name]["size"] = this->wl_spec_info[ws_name]["size"].ToInt() + change;
        sgx_thread_mutex_unlock(&wl_spec_info_mutex);
    }
}

/**
 * @description: Get workload spec info reference
 * @return: Const reference to wl_spec_infop
 */
const json::JSON &Workload::get_wl_spec()
{
    return this->wl_spec_info;
}

/*
 * @description: Restore workload spec information from data
 * @param data -> Workload spec information
 */
void Workload::restore_wl_spec_info(std::string data)
{
    this->wl_spec_info = json::JSON::Load(data);
}

/**
 * @description: Set chain account id
 * @param account_id -> Chain account id
 */
void Workload::set_account_id(std::string account_id)
{
    this->account_id = account_id;
}

/**
 * @description: Get chain account id
 * @return: Chain account id
 */
std::string Workload::get_account_id()
{
    return this->account_id;
}

/**
 * @description: Can get key pair or not
 * @return: Get result
 */
bool Workload::try_get_key_pair()
{
    return this->is_set_key_pair;
}

/**
 * @description: Get public key
 * @return: Const reference to public key
 */
const sgx_ec256_public_t &Workload::get_pub_key()
{
    return this->id_key_pair.pub_key;
}

/**
 * @description: Get private key
 * @return: Const reference to private key
 */
const sgx_ec256_private_t &Workload::get_pri_key()
{
    return this->id_key_pair.pri_key;
}

/**
 * @description: Set identity key pair
 * @param id_key_pair -> Identity key pair
 */
void Workload::set_key_pair(ecc_key_pair id_key_pair)
{
    memcpy(&this->id_key_pair.pub_key, &id_key_pair.pub_key, sizeof(sgx_ec256_public_t));
    memcpy(&this->id_key_pair.pri_key, &id_key_pair.pri_key, sizeof(sgx_ec256_private_t));
    this->is_set_key_pair = true;
}

/**
 * @description: Get identity key pair
 * @return: Const reference to identity key pair
 */
const ecc_key_pair &Workload::get_key_pair()
{
    return this->id_key_pair;
}

/**
 * @description: Set MR enclave
 * @param mr -> MR enclave
 */
void Workload::set_mr_enclave(sgx_measurement_t mr)
{
    memcpy(&this->mr_enclave, &mr, sizeof(sgx_measurement_t));
}

/**
 * @description: Get MR enclave
 * @return: Const reference to MR enclave
 */
const sgx_measurement_t &Workload::get_mr_enclave()
{
    return this->mr_enclave;
}

/**
 * @description: Set report height
 * @param height -> Report height
 */
void Workload::set_report_height(size_t height)
{
    this->report_height = height;
}

/**
 * @description: Get report height
 * @return: Report height
 */
size_t Workload::get_report_height()
{
    return this->report_height;
}

/**
 * @description: Set restart flag
 */
void Workload::set_restart_flag()
{
    this->restart_flag = 4;
}

/**
 * @description: Reduce flag
 */
void Workload::reduce_restart_flag()
{
    this->restart_flag -= 1;
    if (this->restart_flag < 0)
    {
        this->restart_flag = 0;
    }
}

/**
 * @description: Get restart flag
 * @return: Restart flag
 */
bool Workload::get_restart_flag()
{
    return this->restart_flag > 0;
}

/**
 * @description: add validated proof
 */
void Workload::report_add_validated_proof()
{
    sgx_thread_mutex_lock(&this->validated_mutex);
    if (this->validated_proof >= 2)
    {
        this->validated_proof = 2;
    }
    else
    {
        this->validated_proof++;
    }
    sgx_thread_mutex_unlock(&this->validated_mutex);
}

/**
 * @description: reduce validated proof
 */
void Workload::report_reduce_validated_proof()
{
    sgx_thread_mutex_lock(&this->validated_mutex);
    if (this->validated_proof <= 0)
    {
        this->validated_proof = 0;
    }
    else
    {
        this->validated_proof--;
    }
    sgx_thread_mutex_unlock(&this->validated_mutex);
}

/**
 * @description: Has validated proof
 * @return: true or false
 */
bool Workload::report_has_validated_proof()
{
    sgx_thread_mutex_lock(&this->validated_mutex);
    bool res = (this->validated_proof > 0);
    sgx_thread_mutex_unlock(&this->validated_mutex);

    return res;
}

/**
 * @description: Add deleted srd to buffer
 * @param path -> Srd deleted path
 * @param index -> Srd index in indicated path
 * @return: Add result
 */
bool Workload::add_srd_to_deleted_buffer(std::string path, uint32_t index)
{
    sgx_thread_mutex_lock(&this->srd_del_path2idx_mutex);
    auto ret_val = this->srd_del_path2idx_um[path].insert(index);
    sgx_thread_mutex_unlock(&this->srd_del_path2idx_mutex);

    return ret_val.second;
}

/**
 * @description: Has given srd been added to buffer
 * @param path -> Srd deleted path
 * @param index -> Srd index in indicated path
 * @return: Added to deleted buffer or not
 */
bool Workload::is_srd_in_deleted_buffer(std::string path, uint32_t index)
{
    sgx_thread_mutex_lock(&this->srd_del_path2idx_mutex);
    bool ret = (this->srd_del_path2idx_um[path].find(index) != this->srd_del_path2idx_um[path].end());
    sgx_thread_mutex_unlock(&this->srd_del_path2idx_mutex);

    return ret;
}

/**
 * @description: Delete invalid srd from metadata
 * @param locked -> Lock srd_path2hashs_m or not
 */
void Workload::deal_deleted_srd(bool locked)
{
    // Delete related srd from metadata by mainloop thread
    if (locked)
    {
        sgx_thread_mutex_lock(&this->srd_mutex);
    }

    sgx_thread_mutex_lock(&this->srd_del_path2idx_mutex);
    std::unordered_map<std::string, std::set<uint32_t>> tmp_del_path2idx_um;
    // Put to be deleted srd to a buffer map and clean the old one
    tmp_del_path2idx_um.insert(this->srd_del_path2idx_um.begin(), this->srd_del_path2idx_um.end());
    this->srd_del_path2idx_um.clear();
    sgx_thread_mutex_unlock(&this->srd_del_path2idx_mutex);

    for (auto path2idx : tmp_del_path2idx_um)
    {
        std::string del_dir = path2idx.first;
        std::set<uint32_t> *deleted_idx = &path2idx.second;
        if (this->srd_path2hashs_m.find(del_dir) != this->srd_path2hashs_m.end())
        {
            size_t del_num = 0;
            std::vector<uint8_t *> *p_hashs = &this->srd_path2hashs_m[del_dir];
            for (auto index_rit = deleted_idx->rbegin(); index_rit != deleted_idx->rend(); index_rit++)
            {
                if (*index_rit < p_hashs->size())
                {
                    if ((*p_hashs)[*index_rit] != NULL)
                    {
                        free((*p_hashs)[*index_rit]);
                    }
                    p_hashs->erase(p_hashs->begin() + *index_rit);
                    del_num++;
                    if (0 == p_hashs->size())
                    {
                        this->srd_path2hashs_m.erase(del_dir);
                        break;
                    }
                }
            }
            this->set_srd_info(del_dir, -del_num);
        }
    }

    if (locked)
    {
        sgx_thread_mutex_unlock(&this->srd_mutex);
    }
}

/**
 * @description: Add file to deleted buffer
 * @param index -> File index
 * @return: Added result
 */
bool Workload::add_to_deleted_file_buffer(uint32_t index)
{
    sgx_thread_mutex_lock(&this->file_del_idx_mutex);
    auto ret = this->file_del_idx_s.insert(index);
    sgx_thread_mutex_unlock(&this->file_del_idx_mutex);

    return ret.second;
}

/**
 * @description: Is deleted file in buffer
 * @param index -> File index
 * @return: Check result
 */
bool Workload::is_in_deleted_file_buffer(uint32_t index)
{
    sgx_thread_mutex_lock(&this->file_del_idx_mutex);
    bool ret = (this->file_del_idx_s.find(index) != this->file_del_idx_s.end());
    sgx_thread_mutex_unlock(&this->file_del_idx_mutex);

    return ret;
}

/**
 * @description: Recover file from deleted buffer
 * @param index -> File index
 */
void Workload::recover_from_deleted_file_buffer(uint32_t index)
{
    sgx_thread_mutex_lock(&this->file_del_idx_mutex);
    this->file_del_idx_s.erase(index);
    sgx_thread_mutex_unlock(&this->file_del_idx_mutex);
}

/**
 * @description: Deal with deleted file
 */
void Workload::deal_deleted_file()
{
    SafeLock sealed_files_sl(this->file_mutex);
    sealed_files_sl.lock();

    std::set<uint32_t> tmp_del_idx_s;
    sgx_thread_mutex_lock(&this->file_del_idx_mutex);
    tmp_del_idx_s.insert(this->file_del_idx_s.begin(), this->file_del_idx_s.end());
    this->file_del_idx_s.clear();
    sgx_thread_mutex_unlock(&this->file_del_idx_mutex);

    for (auto index : tmp_del_idx_s)
    {
        this->sealed_files[index][FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
    }
    // Deleted invalid file item
    for (auto it = this->sealed_files.begin(); it != this->sealed_files.end();)
    {
        std::string status = (*it)[FILE_STATUS].ToString();
        if ((status[CURRENT_STATUS] == FILE_STATUS_DELETED && status[ORIGIN_STATUS] == FILE_STATUS_DELETED)
                || (status[CURRENT_STATUS] == FILE_STATUS_DELETED && status[ORIGIN_STATUS] == FILE_STATUS_UNVERIFIED))
        {
            it = this->sealed_files.erase(it);
        }
        else
        {
            it++;
        }
    }
    sealed_files_sl.unlock();
}

/**
 * @description: Is file duplicated
 * @param cid -> File's content id
 * @return: File duplicated or not
 */
bool Workload::is_file_dup(std::string cid)
{
    size_t pos = 0;
    return is_file_dup(cid, pos);
}

/**
 * @description: Is file duplicated
 * @param cid -> File's content id
 * @param pos -> Duplicated file's position
 * @return: Duplicated or not
 */
bool Workload::is_file_dup(std::string cid, size_t &pos)
{
    long spos = 0;
    long epos = this->sealed_files.size();
    while (spos < epos)
    {
        long mpos = (spos + epos) / 2;
        int ret = cid.compare(this->sealed_files[mpos][FILE_CID].ToString());
        if (ret > 0)
        {
            spos = mpos + 1;
        }
        else if (ret < 0)
        {
            epos = mpos - 1;
        }
        else
        {
            pos = mpos;
            return true;;
        }
    }

    pos = spos;
    return false;
}

/**
 * @description: Add sealed file
 * @param file -> File content
 * @param pos -> Inserted position
 */
void Workload::add_sealed_file(json::JSON file, size_t pos)
{
    if (pos <= this->sealed_files.size())
    {
        this->sealed_files.insert(this->sealed_files.begin() + pos, file);
    }
}

/**
 * @description: Add sealed file
 * @param file -> File content
 */
void Workload::add_sealed_file(json::JSON file)
{
    size_t pos = 0;
    if (is_file_dup(file[FILE_CID].ToString(), pos))
    {
        return;
    }

    this->sealed_files.insert(this->sealed_files.begin() + pos, file);
}
