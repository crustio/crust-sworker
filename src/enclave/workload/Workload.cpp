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
 */
std::string Workload::get_workload(void)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sha256_hash_t srd_root;
    size_t srd_workload = 0;
    json::JSON wl_json;
    json::JSON md_json;
    memset(srd_root, 0, sizeof(sgx_sha256_hash_t));

    // ----- workload info ----- //
    id_get_metadata(md_json);
    // Srd info
    this->get_srd_info(&srd_root, &srd_workload, md_json);
    wl_json[WL_SRD][WL_SRD_ROOT_HASH] = hexstring_safe(srd_root, HASH_LENGTH);
    wl_json[WL_SRD][WL_SRD_SPACE] = srd_workload / 1024 / 1024 / 1024;
    wl_json[WL_SRD][WL_SRD_REMAINING_TASK] = get_srd_change();
    // file info
    if (md_json.hasKey(ID_FILE) && md_json[ID_FILE].size() > 0)
    {
        for (int i = 0; i < md_json[ID_FILE].size(); i++)
        {
            json::JSON tmp_json;
            tmp_json[WL_FILE_SEALED_SIZE] = md_json[ID_FILE][i][FILE_SIZE];
            tmp_json[WL_FILE_STATUS] = md_json[ID_FILE][i][FILE_STATUS];
            // Get old hash
            uint8_t *p_meta = NULL;
            size_t meta_len = 0;
            crust_status = persist_get((md_json[ID_FILE][i][FILE_HASH].ToString()+"_meta").c_str(), &p_meta, &meta_len);
            if (CRUST_SUCCESS == crust_status && p_meta != NULL)
            {
                json::JSON org_file_json = json::JSON::Load(std::string(reinterpret_cast<char*>(p_meta), meta_len));
                free(p_meta);
                tmp_json[WL_FILE_OLD_HASH] = org_file_json[FILE_OLD_HASH].ToString();
                tmp_json[WL_FILE_OLD_SIZE] = org_file_json[FILE_OLD_SIZE].ToInt();
            }
            std::string tmp_str = tmp_json.dump();
            remove_char(tmp_str, '\n');
            wl_json[WL_FILES][md_json[ID_FILE][i][FILE_HASH].ToString()] = tmp_str;
        }
    }

    // Store workload
    std::string wl_str = wl_json.dump();
    ocall_store_workload(wl_str.c_str());

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
crust_status_t Workload::get_srd_info(sgx_sha256_hash_t *srd_root_out, size_t *srd_workload_out, json::JSON &md_json)
{
    if (! md_json.hasKey(ID_WORKLOAD) 
            || md_json[ID_WORKLOAD].JSONType() != json::JSON::Class::Object)
    {
        return CRUST_SUCCESS;
    }
    // Get hashs for hashing
    size_t g_hashs_num = 0;
    for (auto it = md_json[ID_WORKLOAD].ObjectRange().begin();
            it != md_json[ID_WORKLOAD].ObjectRange().end(); it++)
    {
        g_hashs_num += it->second.size();
    }
    unsigned char *hashs = (unsigned char *)malloc(g_hashs_num * HASH_LENGTH);
    size_t hashs_len = 0;

    for (auto it = md_json[ID_WORKLOAD].ObjectRange().begin();
            it != md_json[ID_WORKLOAD].ObjectRange().end(); it++)
    {
        for (int i = 0; i < it->second.size(); i++)
        {
            std::string hash_str = it->second[i].ToString();
            uint8_t *hash_u = hex_string_to_bytes(hash_str.c_str(), hash_str.size());
            memcpy(hashs + hashs_len, hash_u, HASH_LENGTH);
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
        sgx_sha256_msg(hashs, (uint32_t)hashs_len, srd_root_out);
    }

    free(hashs);

    return CRUST_SUCCESS;
}

/**
 * @description: Serialize workload for sealing
 * @param locked -> Indicates whether to get lock, default value is true
 * @return: Serialized workload
 */
json::JSON Workload::serialize_srd(bool locked /*=true*/)
{
    if (locked)
    {
        sgx_thread_mutex_lock(&g_srd_mutex);
    }

    // Store srd_path2hashs_m
    json::JSON g_hashs_json;
    for (auto it : this->srd_path2hashs_m)
    {
        int i = 0;
        for (auto g_hash : it.second)
        {
            g_hashs_json[it.first][i++] = hexstring_safe(g_hash, HASH_LENGTH);
        }
    }

    if (locked)
    {
        sgx_thread_mutex_unlock(&g_srd_mutex);
    }

    return g_hashs_json;
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
            uint8_t *g_hash = hex_string_to_bytes(it->second[i].ToString().c_str(), it->second[i].ToString().size());
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
