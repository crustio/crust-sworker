#include "Workload.h"

extern ecc_key_pair id_key_pair;
sgx_thread_mutex_t g_workload_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_checked_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_new_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t g_order_files_mutex = SGX_THREAD_MUTEX_INITIALIZER;

Workload *Workload::workload = NULL;

/**
 * @desination: single instance class function to get instance
 * @return: workload instance
 * */
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
 * @description: destructor
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
 * @description: print work report
 */
void Workload::show(void)
{
    sgx_sha256_hash_t empty_root;
    size_t empty_workload = 0;
    this->generate_empty_info(&empty_root, &empty_workload);

    // Print srd info
    log_debug("Empty root hash: %s\n", unsigned_char_array_to_hex_string(empty_root, HASH_LENGTH).c_str());
    log_debug("Empty workload: %luG\n", empty_workload / 1024 / 1024 / 1024);

    // Print meaningful file info
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    if (this->checked_files.size() == 0)
    {
        log_debug("No meaningful file.\n");
    }
    else
    {
        log_debug("Meaningful work details is: \n");
        for (uint32_t i = 0; i < this->checked_files.size(); i++)
        {
            log_debug("Meaningful root hash:%s -> size: %-11ld status: %s\n",
                      this->checked_files[i]["hash"].ToString().c_str(), 
                      this->checked_files[i]["size"].ToInt(),
                      this->checked_files[i]["status"].ToString().c_str());
        }
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

/**
 * @description: Clean up work report data
 * */
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
 * @description: generate empty information
 * @param empty_root_out empty root hash
 * @param empty_workload_out empty workload
 * @return: status
 */
crust_status_t Workload::generate_empty_info(sgx_sha256_hash_t *empty_root_out, size_t *empty_workload_out)
{
    sgx_thread_mutex_lock(&g_workload_mutex);

    // Get hashs for hashing
    size_t g_hashs_num = 0;
    for (auto it : this->srd_path2hashs_m)
    {
        g_hashs_num += it.second.size();
    }
    unsigned char *hashs = (unsigned char *)malloc(g_hashs_num * HASH_LENGTH);
    size_t hashs_len = 0;

    for (auto it : this->srd_path2hashs_m)
    {
        for (auto g_hash : it.second)
        {
            memcpy(hashs + hashs_len, g_hash, HASH_LENGTH);
            hashs_len += HASH_LENGTH;
        }
    }

    // generate empty information
    if (hashs_len == 0)
    {
        *empty_workload_out = 0;
        memset(empty_root_out, 0, HASH_LENGTH);
    }
    else
    {
        *empty_workload_out = (hashs_len / HASH_LENGTH) * 1024 * 1024 * 1024;
        sgx_sha256_msg(hashs, (uint32_t)hashs_len, empty_root_out);
    }

    free(hashs);

    sgx_thread_mutex_unlock(&g_workload_mutex);
    return CRUST_SUCCESS;
}

/**
 * @description: serialize workload for sealing
 * @return: serialized workload
 * */
std::string Workload::serialize_workload(bool locked /*=true*/)
{
    if (locked)
    {
        sgx_thread_mutex_lock(&g_workload_mutex);
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
        sgx_thread_mutex_unlock(&g_workload_mutex);
    }

    std::string g_hashs_str = g_hashs_json.dump();
    remove_char(g_hashs_str, '\\');
    remove_char(g_hashs_str, '\n');
    remove_char(g_hashs_str, ' ');

    return g_hashs_str;
}

/**
 * @description: Restore workload from serialized workload
 * @return: Restore status
 * */
crust_status_t Workload::restore_workload(json::JSON g_hashs)
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

bool Workload::reset_meaningful_data()
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);

    this->checked_files.clear();

    // Get metadata
    json::JSON meta_json;
    id_get_metadata(meta_json);

    // Reset meaningful files
    if (!meta_json.hasKey(MEANINGFUL_FILE_DB_TAG))
    {
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
        return true;
    }

    json::JSON meaningful_files = meta_json[MEANINGFUL_FILE_DB_TAG];
    if (meaningful_files.JSONType() == json::JSON::Class::Array)
    {
        for (int i = 0; i < meaningful_files.size(); i++)
        {
            this->checked_files.push_back(meaningful_files[i]);
        }
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
        return true;
    }

    log_warn("Workload: invalid meaningful roots! Set meaningful files to empty.\n");

    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    return true;
}

/**
 * @description: Add new file to new_files
 * @param file -> A pair of file's hash and file's size
 * */
void Workload::add_new_file(json::JSON file)
{
    sgx_thread_mutex_lock(&g_new_files_mutex);
    this->new_files.push_back(file);
    sgx_thread_mutex_unlock(&g_new_files_mutex);
}

/**
 * @description: Add new order file to order_files
 * @param file -> A pair of file's hash and file's size
 * */
void Workload::add_order_file(std::pair<std::string, size_t> file)
{
    sgx_thread_mutex_lock(&g_order_files_mutex);
    this->order_files.push_back(file);
    sgx_thread_mutex_unlock(&g_order_files_mutex);
}
