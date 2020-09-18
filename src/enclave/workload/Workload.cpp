#include "Workload.h"

sgx_thread_mutex_t g_workload_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_srd_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_checked_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_new_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_order_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
    sgx_sha256_hash_t srd_root;
    uint64_t srd_workload = 0;
    json::JSON md_json;
    memset(srd_root, 0, sizeof(sgx_sha256_hash_t));
    std::string wl_str;

    // ----- workload info ----- //
    id_get_metadata(md_json);
    // file info
    wl_str.append("{");
    wl_str.append("\"").append(WL_FILES).append("\":{");
    if (md_json.hasKey(ID_FILE) && md_json[ID_FILE].size() > 0)
    {
        for (int i = 0; i < md_json[ID_FILE].size(); i++)
        {
            std::string tmp_str = "{";
            tmp_str.append("\"").append(WL_FILE_SEALED_SIZE).append("\":")
                .append(std::to_string(md_json[ID_FILE][i][FILE_SIZE].ToInt())).append(",");
            tmp_str.append("\"").append(WL_FILE_STATUS).append("\":")
                .append("\"").append(md_json[ID_FILE][i][FILE_STATUS].ToString()).append("\"}");
            wl_str.append("\"").append(md_json[ID_FILE][i][FILE_HASH].ToString()).append("\":").append(tmp_str);
            if (i != md_json[ID_FILE].size() - 1)
            {
                wl_str.append(",");
            }
        }
    }
    wl_str.append("},");
    // Srd info
    this->get_srd_info(&srd_root, &srd_workload, md_json);
    wl_str.append("\"").append(WL_SRD).append("\":{");
    wl_str.append("\"").append(WL_SRD_ROOT_HASH).append("\":")
        .append("\"").append(hexstring_safe(srd_root, HASH_LENGTH)).append("\",");
    wl_str.append("\"").append(WL_SRD_SPACE).append("\":")
        .append(std::to_string(srd_workload / 1024 / 1024 / 1024)).append(",");
    wl_str.append("\"").append(WL_SRD_REMAINING_TASK).append("\":")
        .append("\"").append(std::to_string(get_srd_change())).append("\"}");
    wl_str.append("}");

    // Store workload
    store_large_data(wl_str, ocall_store_workload, Workload::get_instance()->ocall_wl_mutex);

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
 * @description: Serialize workload for sealing
 * @param locked -> Indicates whether to get lock, default value is true
 * @return: Serialized workload
 */
std::string Workload::serialize_srd(bool locked /*=true*/)
{
    if (locked)
    {
        sgx_thread_mutex_lock(&g_srd_mutex);
    }

    // Store srd_path2hashs_m
    std::string ans;

    size_t i = 0;
    ans.append("{");
    for (auto it = this->srd_path2hashs_m.begin(); it != this->srd_path2hashs_m.end(); it++, i++)
    {
        ans.append("\"").append(it->first).append("\":[");
        for (size_t j = 0; j < it->second.size(); j++)
        {
            ans.append("\"").append(hexstring_safe(it->second[j], HASH_LENGTH)).append("\"");
            if (j != it->second.size() - 1)
            {
                ans.append(",");
            }
        }
        ans.append("]");
        if (i != this->srd_path2hashs_m.size() - 1)
        {
            ans.append(",");
        }
    }
    ans.append("}");

    if (locked)
    {
        sgx_thread_mutex_unlock(&g_srd_mutex);
    }

    return ans;
}

/**
 * @description: Serialize file for sealing
 * @param locked -> Indicates whether to get lock, default value is true
 * @return: Serialized file info
 */
std::string Workload::serialize_file(bool locked /*=true*/)
{
    if (locked)
    {
        sgx_thread_mutex_lock(&g_checked_files_mutex);
    }

    std::string ans;

    ans.append("[");
    for (size_t i = 0; i < this->checked_files.size(); i++)
    {
        ans.append(this->checked_files[i].dump());
        if (i != this->checked_files.size() - 1)
        {
            ans.append(",");
        }
    }
    ans.append("]");

    if (locked)
    {
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
    }

    return ans;
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

    return crust_status;
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
 * @description: Add new order file to order_files
 * @param file -> A pair of file's hash and file's size
 */
void Workload::add_order_file(std::pair<std::string, size_t> file)
{
    sgx_thread_mutex_lock(&g_order_files_mutex);
    this->order_files.push_back(file);
    sgx_thread_mutex_unlock(&g_order_files_mutex);
}

/**
 * @description: Set report file flag
 * @param flag -> Report flag
 */
void Workload::set_report_flag(bool flag)
{
    this->report_files = flag;
}

/**
 * @description: Get report flag
 * @return: Report flag
 */
bool Workload::get_report_flag()
{
    return this->report_files;
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
    sgx_thread_mutex_unlock(&this->srd_info_mutex);
}

/**
 * @description: Get srd info
 * @return: Return srd info json
 */
json::JSON Workload::get_srd_info()
{
    return this->srd_info_json;
}
