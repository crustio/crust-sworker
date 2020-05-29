#include "Workload.h"

extern ecc_key_pair id_key_pair;
sgx_thread_mutex_t g_workload_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
    for (auto g_hash : this->empty_g_hashs)
    {
        if (g_hash != NULL)
            free(g_hash);
    }
    this->empty_g_hashs.clear();
}

/**
 * @description: print work report
 */
void Workload::show(void)
{
    sgx_sha256_hash_t empty_root;
    size_t empty_workload = 0;
    this->generate_empty_info(&empty_root, &empty_workload);

    log_debug("Empty root hash: %s\n", unsigned_char_array_to_hex_string(empty_root, HASH_LENGTH).c_str());
    log_debug("Empty workload: %luG\n", empty_workload / 1024 / 1024 / 1024);

    log_debug("Meaningful work details is: \n");
    for (int i = 0; i < this->files_json.size(); i++)
    {
        log_debug("Meaningful root hash:%s -> size:%ld\n",
                  this->files_json[i]["hash"].ToString().c_str(), this->files_json[i]["size"].ToInt());
    }
}

/**
 * @description: Clean up work report data
 * */
void Workload::clean_data()
{
    // Clean empty_g_hashs
    for (auto g_hash : this->empty_g_hashs)
    {
        if (g_hash != NULL)
            free(g_hash);
    }
    this->empty_g_hashs.clear();
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
    unsigned char *hashs = (unsigned char *)malloc(this->empty_g_hashs.size() * HASH_LENGTH);
    size_t hashs_length = 0;

    for (auto g_hash : this->empty_g_hashs)
    {
        for (size_t j = 0; j < HASH_LENGTH; j++)
        {
            hashs[hashs_length + j] = g_hash[j];
        }
        hashs_length += HASH_LENGTH;
    }

    // generate empty information
    if (hashs_length == 0)
    {
        *empty_workload_out = 0;
        for (size_t i = 0; i < HASH_LENGTH; i++)
        {
            (*empty_root_out)[i] = 0;
        }
    }
    else
    {
        *empty_workload_out = (hashs_length / HASH_LENGTH) * 1024 * 1024 * 1024;
        sgx_sha256_msg(hashs, (uint32_t)hashs_length, empty_root_out);
    }

    free(hashs);

    sgx_thread_mutex_unlock(&g_workload_mutex);
    return CRUST_SUCCESS;
}

/**
 * @description: serialize workload for sealing
 * @return: serialized workload
 * */
std::string Workload::serialize_workload()
{
    sgx_thread_mutex_lock(&g_workload_mutex);

    // Store empty_g_hashs
    json::JSON g_hashs;
    int i = 0;
    for (auto it = this->empty_g_hashs.begin(); it != this->empty_g_hashs.end(); it++, i++)
    {
        char *p_hexstr = hexstring_safe(*it, HASH_LENGTH);
        g_hashs[i] = std::string(p_hexstr, HASH_LENGTH * 2);
        if (p_hexstr != NULL)
        {
            free(p_hexstr);
        }
    }

    sgx_thread_mutex_unlock(&g_workload_mutex);

    std::string g_hashs_str = g_hashs.dump();
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

    // Get empty_g_hashs
    for (auto it : this->empty_g_hashs)
    {
        if (it != NULL)
            free(it);
    }
    this->empty_g_hashs.clear(); // Clear current empty_g_hashs
    // Restore g_hashs
    for (int i = 0; i < g_hashs.size(); i++)
    {
        std::string g_hash_str = g_hashs[i].ToString();
        uint8_t *g_hash = hex_string_to_bytes(g_hash_str.c_str(), g_hash_str.size());
        if (g_hash == NULL)
        {
            clean_data();
            return CRUST_UNEXPECTED_ERROR;
        }
        this->empty_g_hashs.push_back(g_hash);
    }

    return crust_status;
}

bool Workload::reset_meaningful_data()
{
    // Get metadata
    json::JSON meta_json;
    id_get_metadata(meta_json);

    // Reset meaningful files
    if (!meta_json.hasKey(MEANINGFUL_FILE_DB_TAG))
    {
        this->files_json = json::Array();
        return true;
    }

    json::JSON meaningful_files = meta_json[MEANINGFUL_FILE_DB_TAG];
    if (meaningful_files.JSONType() == json::JSON::Class::Array)
    {
        this->files_json = meaningful_files;
        return true;
    }

    log_warn("Workload: invalid meaningful roots! Set meaningful files to empty.\n");

    this->files_json = json::Array();

    return true;
}
