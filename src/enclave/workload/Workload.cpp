#include "Workload.h"

sgx_thread_mutex_t g_workload_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_srd_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_checked_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_new_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_report_flag_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
    wl_json[WL_FILES] = this->wl_spec_info;
    // Srd info
    wl_json[WL_SRD][WL_SRD_DETAIL] = this->get_srd_info();
    wl_json[WL_SRD][WL_SRD_REMAINING_TASK] = get_srd_change();

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
void Workload::clean_data()
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
 * @description: Generate srd information
 * @param srd_root_out -> srd root hash
 * @param srd_workload_out -> srd workload
 * @return: Get status
 */
crust_status_t Workload::get_srd_info(sgx_sha256_hash_t *srd_root_out, uint64_t *srd_workload_out, json::JSON &md_json)
{
    if (! md_json.hasKey(ID_WORKLOAD) 
            || md_json[ID_WORKLOAD].JSONType() != json::JSON::Class::Object)
    {
        return CRUST_SUCCESS;
    }
    // Get hashs for hashing
    uint64_t g_hashs_num = 0;
    for (auto it = md_json[ID_WORKLOAD].ObjectRange().begin();
            it != md_json[ID_WORKLOAD].ObjectRange().end(); it++)
    {
        g_hashs_num += it->second.size();
    }
    uint8_t *hashs = (uint8_t *)enc_malloc(g_hashs_num * HASH_LENGTH);
    if (hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    uint64_t hashs_len = 0;

    for (auto it = md_json[ID_WORKLOAD].ObjectRange().begin();
            it != md_json[ID_WORKLOAD].ObjectRange().end(); it++)
    {
        for (int i = 0; i < it->second.size(); i++)
        {
            std::string hash_str = it->second[i].ToString();
            uint8_t *hash_u = hex_string_to_bytes(hash_str.c_str(), hash_str.size());
            if (hash_u == NULL)
            {
                free(hashs);
                return CRUST_MALLOC_FAILED;
            }
            memcpy(hashs + hashs_len, hash_u, HASH_LENGTH);
            free(hash_u);
            hashs_len += HASH_LENGTH;
        }
    }

    // generate srd information
    if (hashs_len == 0)
    {
        *srd_workload_out = 0;
        memset(srd_root_out, 0, HASH_LENGTH);
    }
    else
    {
        *srd_workload_out = (hashs_len / HASH_LENGTH) * 1024 * 1024 * 1024;
        sgx_sha256_msg(hashs, hashs_len, srd_root_out);
    }

    free(hashs);

    return CRUST_SUCCESS;
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
    if (this->checked_files.size() == 0)
    {
        memset(&file_root, 0, sizeof(sgx_sha256_hash_t));
        ans[WL_FILE_ROOT_HASH] = reinterpret_cast<uint8_t *>(&file_root);
    }
    else
    {
        uint8_t *f_hashs = (uint8_t *)enc_malloc(this->checked_files.size() * HASH_LENGTH);
        memset(f_hashs, 0, this->checked_files.size() * HASH_LENGTH);
        size_t f_hashs_len = 0;
        for (size_t i = 0; i < this->checked_files.size(); i++)
        {
            std::string f_hash = this->checked_files[i][FILE_HASH].ToString();
            uint8_t *f_hash_u = hex_string_to_bytes(f_hash.c_str(), f_hash.size());
            if (f_hash_u == NULL)
            {
                return ans;
            }
            memcpy(f_hashs + f_hashs_len, f_hash_u, HASH_LENGTH);
            free(f_hash_u);
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
 * @param locked -> Indicates whether to get lock, default value is true
 * @return: Serialized workload
 */
void Workload::serialize_srd(std::string &sered_srd)
{
    sgx_thread_mutex_lock(&g_srd_mutex);

    size_t i = 0;
    sered_srd.append("{");
    for (auto it = this->srd_path2hashs_m.begin(); it != this->srd_path2hashs_m.end(); it++, i++)
    {
        sered_srd.append("\"").append(it->first).append("\":[");
        for (size_t j = 0; j < it->second.size(); j++)
        {
            sered_srd.append("\"").append(hexstring_safe(it->second[j], HASH_LENGTH)).append("\"");
            if (j != it->second.size() - 1)
            {
                sered_srd.append(",");
            }
        }
        sered_srd.append("]");
        if (i != this->srd_path2hashs_m.size() - 1)
        {
            sered_srd.append(",");
        }
    }
    sered_srd.append("}");

    sgx_thread_mutex_unlock(&g_srd_mutex);
}

/**
 * @description: Serialize file for sealing
 * @param locked -> Indicates whether to get lock, default value is true
 * @return: Serialized file info
 */
crust_status_t Workload::serialize_file(uint8_t **p_data, size_t *data_size)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);

    size_t file_item_len = strlen(FILE_HASH) + 3 + strlen(HASH_TAG) + 64 + 3
        + strlen(FILE_OLD_HASH) + 3 + strlen(HASH_TAG) + 64 + 3
        + strlen(FILE_SIZE) + 3 + 12 + 1
        + strlen(FILE_OLD_SIZE) + 3 + 12 + 1
        + strlen(FILE_BLOCK_NUM) + 3 + 6 + 1
        + strlen(FILE_STATUS) + 3 + 3 + 3
        + 2;
    size_t buffer_size = this->checked_files.size() * file_item_len;
    *p_data = (uint8_t *)enc_malloc(buffer_size);
    if (*p_data == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(*p_data, 0, buffer_size);
    size_t offset = 0;

    memcpy(*p_data + offset, "[", 1);
    offset += 1;
    for (size_t i = 0; i < this->checked_files.size(); i++)
    {
        std::string file_str = this->checked_files[i].dump();
        remove_char(file_str, '\n');
        remove_char(file_str, '\\');
        remove_char(file_str, ' ');
        if (i != this->checked_files.size() - 1)
        {
            file_str.append(",");
        }
        memcpy(*p_data + offset, file_str.c_str(), file_str.size());
        offset += file_str.size();
    }
    memcpy(*p_data + offset, "]", 1);
    offset += 1;

    *data_size = offset;

    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    return CRUST_SUCCESS;
}

/**
 * @description: Restore workload from serialized workload
 * @param g_hashs -> G hashs in json format
 * @return: Restore status
 */
crust_status_t Workload::restore_srd(json::JSON g_hashs)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    // Get srd_path2hashs_m
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
                clean_data();
                return CRUST_UNEXPECTED_ERROR;
            }
            this->srd_path2hashs_m[it->first].push_back(g_hash);
        }
    }
    // Restore srd info
    for (auto it : this->srd_path2hashs_m)
    {
        this->srd_info_json[it.first]["assigned"] = it.second.size();
    }

    return crust_status;
}

/**
 * @description: Restore file from json
 * @param file_json -> File json
 */
void Workload::restore_file(json::JSON file_json)
{
    this->checked_files.clear();
    for (int i = 0; i < file_json.size(); i++)
    {
        this->checked_files.push_back(file_json[i]);
    }
}

/**
 * @description: Add new file to new_files
 * @param file -> A pair of file's hash and file's size
 */
void Workload::add_new_file(json::JSON file)
{
    sgx_thread_mutex_lock(&g_new_files_mutex);
    this->new_files.push_back(file);
    sgx_thread_mutex_unlock(&g_new_files_mutex);
}

/**
 * @description: Set report file flag
 * @param flag -> Report flag
 */
void Workload::set_report_flag(bool flag)
{
    sgx_thread_mutex_lock(&g_report_flag_mutex);
    this->report_files = flag;
    sgx_thread_mutex_unlock(&g_report_flag_mutex);
}

/**
 * @description: Get report flag
 * @return: Report flag
 */
bool Workload::get_report_flag()
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
    if (this->srd_info_json[path]["assigned"].ToInt() < 0)
    {
        this->srd_info_json[path]["assigned"] = 0;
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
    json::JSON srd_info = this->srd_info_json;
    sgx_thread_mutex_unlock(&this->srd_info_mutex);

    return srd_info;
}

/**
 * @description: Set upgrade flag
 * @param flag -> Upgrade flag
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
 * @param flag -> Is upgrading
 */
void Workload::set_upgrade_status(enc_upgrade_status_t status)
{
    this->upgrade_status = status;
}

/**
 * @description: Get is_upgrading flag
 * @return: Is upgrading
 * */
enc_upgrade_status_t Workload::get_upgrade_status()
{
    return this->upgrade_status;
}

/**
 * @description: Handle workreport result
 * @param report_res -> Workreport result
 */
void Workload::handle_report_result()
{
    // Set file status by report result
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    for (auto i : this->reported_files_idx)
    {
        if (i < this->checked_files.size())
        {
            auto status = &this->checked_files[i][FILE_STATUS];
            status->set_char(ORIGIN_STATUS, status->get_char(WAITING_STATUS));
        }
    }
    this->reported_files_idx.clear();
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

/*
 * @description: Get workload spec by file status
 * @param status -> File status
 * @param wl_pair -> Reference to wl_spec_t pair
 * @return: Get result
 */
bool Workload::get_wl_spec_by_file_status(char status, std::pair<wl_spec_t, wl_spec_t> &wl_pair)
{
    bool res = true;

    if (status == FILE_STATUS_VALID)
    {
        wl_pair = std::make_pair(WL_SPEC_FILE_VALID_NUM, WL_SPEC_FILE_VALID_SIZE);
    }
    else if (status == FILE_STATUS_LOST)
    {
        wl_pair = std::make_pair(WL_SPEC_FILE_LOST_NUM, WL_SPEC_FILE_LOST_SIZE);
    }
    else if (status == FILE_STATUS_UNCONFIRMED)
    {
        wl_pair = std::make_pair(WL_SPEC_FILE_UNCONFIRMED_NUM, WL_SPEC_FILE_UNCONFIRMED_SIZE);
    }
    else
    {
        res = false;
    }

    return res;
}

/**
 * @description: Set workload spec information
 * @param wl_spec -> Workload spec
 * @param change -> Spec information change
 */
void Workload::set_wl_spec(wl_spec_t wl_spec, int change)
{
    sgx_thread_mutex_lock(&wl_spec_info_mutex);
    std::string spec_name = wl_spec_m[wl_spec];
    std::string spec_num_name;
    this->wl_spec_info[spec_name] = this->wl_spec_info[spec_name].ToInt() + change;
    switch(wl_spec)
    {
        case WL_SPEC_FILE_VALID_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_VALID_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() + (change > 0 ? 1 : -1);
            break;
        case WL_SPEC_FILE_LOST_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_LOST_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() + (change > 0 ? 1 : -1);
            break;
        case WL_SPEC_FILE_UNCONFIRMED_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_UNCONFIRMED_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() + (change > 0 ? 1 : -1);
            break;
        default:
            log_warn("Inoperable item!\n");
    }
    std::string wl_spec_info_str = this->wl_spec_info.dump();
    remove_char(wl_spec_info_str, '\n');
    remove_char(wl_spec_info_str, '\\');
    remove_char(wl_spec_info_str, ' ');
    persist_set_unsafe(DB_WL_SPEC_INFO, reinterpret_cast<const uint8_t *>(wl_spec_info_str.c_str()), wl_spec_info_str.size());
    sgx_thread_mutex_unlock(&wl_spec_info_mutex);
}

/**
 * @description: Set workload spec information
 * @param wl_spec -> Workload spec
 * @param related_wl_spec -> Related workload spec
 * @param change -> Spec information change
 */
void Workload::set_wl_spec(wl_spec_t wl_spec, wl_spec_t related_wl_spec, int change)
{
    std::string spec_name = wl_spec_m[wl_spec];
    std::string related_spec_name = wl_spec_m[related_wl_spec];
    std::string spec_num_name;
    if (wl_spec == related_wl_spec)
    {
        return;
    }

    sgx_thread_mutex_lock(&wl_spec_info_mutex);
    this->wl_spec_info[spec_name] = this->wl_spec_info[spec_name].ToInt() + change;
    this->wl_spec_info[related_spec_name] = this->wl_spec_info[related_spec_name].ToInt() - change;
    switch(wl_spec)
    {
        case WL_SPEC_FILE_VALID_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_VALID_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() + (change > 0 ? 1 : -1);
            break;
        case WL_SPEC_FILE_LOST_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_LOST_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() + (change > 0 ? 1 : -1);
            break;
        case WL_SPEC_FILE_UNCONFIRMED_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_UNCONFIRMED_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() + (change > 0 ? 1 : -1);
            break;
        default:
            log_warn("Inoperable item!\n");
    }
    switch(related_wl_spec)
    {
        case WL_SPEC_FILE_VALID_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_VALID_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() - (change > 0 ? 1 : -1);
            break;
        case WL_SPEC_FILE_LOST_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_LOST_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() - (change > 0 ? 1 : -1);
            break;
        case WL_SPEC_FILE_UNCONFIRMED_SIZE:
            spec_num_name = wl_spec_m[WL_SPEC_FILE_UNCONFIRMED_NUM];
            this->wl_spec_info[spec_num_name] = this->wl_spec_info[spec_num_name].ToInt() - (change > 0 ? 1 : -1);
            break;
        default:
            log_warn("Inoperable item!\n");
    }
    std::string wl_spec_info_str = this->wl_spec_info.dump();
    remove_char(wl_spec_info_str, '\n');
    remove_char(wl_spec_info_str, '\\');
    remove_char(wl_spec_info_str, ' ');
    persist_set_unsafe(DB_WL_SPEC_INFO, reinterpret_cast<const uint8_t *>(wl_spec_info_str.c_str()), wl_spec_info_str.size());
    sgx_thread_mutex_unlock(&wl_spec_info_mutex);
}

/*
 * @description: Restore workload spec information from data
 * @param data -> Workload spec information
 */
void Workload::restore_wl_spec_info(std::string data)
{
    this->wl_spec_info = json::JSON::Load(data);
}
