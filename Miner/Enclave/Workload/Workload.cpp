#include "Workload.h"

extern ecc_key_pair id_key_pair;
sgx_thread_mutex_t g_workload_mutex = SGX_THREAD_MUTEX_INITIALIZER;
Workload *workload = new Workload();

/**
 * @description: get the global workload
 * @return: the global workload
 */
Workload *get_workload()
{
    return workload;
}

/**
 * @description: constructor
 */
Workload::Workload()
{
    this->empty_disk_capacity = 0;
    for (size_t i = 0; i < 32; i++)
    {
        this->empty_root_hash[i] = 0;
    }
}

/**
 * @description: destructor
 */
Workload::~Workload()
{
    for (size_t i = 0; i < this->empty_g_hashs.size(); i++)
    {
        delete[] this->empty_g_hashs[i];
    }

    this->empty_g_hashs.clear();
}

/**
 * @description: print work report
 */
void Workload::show(void)
{
    log_info("Empty root hash: %s\n", unsigned_char_array_to_hex_string(this->empty_root_hash, HASH_LENGTH).c_str());
    log_info("Empty capacity: %luG\n", this->empty_disk_capacity);

    log_debug("Meaningful work details is: \n");
    size_t total_size = 0;
    for (auto it = this->files.begin(); it != this->files.end(); it++)
    {
        log_debug("Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_string(it->first.data(), HASH_LENGTH).c_str(), it->second);
        total_size += it->second;
    }

    log_info("Meaningful work file number is: %lu, total size %luB\n", this->files.size(), total_size);

}

/**
 * @description: Clean up work report data
 * */
void Workload::clean_data()
{
    // Clean empty_g_hashs
    for(auto it : this->empty_g_hashs)
    {
        if (it != NULL)
            free(it);
    }
    this->empty_g_hashs.clear();

    // Clean files
    this->files.clear();
}

/**
 * @description: serialize work report for reporting to chain
 * @return: the work report
 */
std::string Workload::serialize()
{
    sgx_thread_mutex_lock(&g_workload_mutex);

    this->report = "{";
    this->report += "\"pub_key\":\"" + std::string((const char*)hexstring(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key))) + "\",";
    this->report += "\"empty_root\":\"" + unsigned_char_array_to_hex_string(this->empty_root_hash, HASH_LENGTH) + "\",";
    unsigned long long empty_disk_capacity_ull = this->empty_disk_capacity;
    empty_disk_capacity_ull = empty_disk_capacity_ull * 1024 * 1024 * 1024;
    this->report += "\"empty_workload\":" + std::to_string(empty_disk_capacity_ull) + ",";
    //this->report += "files:[";
    size_t meaningful_workload_size = 0;
    for (auto it = this->files.begin(); it != this->files.end(); it++)
    {
        //report += "{\"hash\":\"" + unsigned_char_array_to_hex_string(it->first.data(), HASH_LENGTH) + "\",\"size\":" + std::to_string(it->second) + "},";
        meaningful_workload_size += it->second;
    }
    this->report += "\"meaningful_workload\":" + std::to_string(meaningful_workload_size);
    this->report += "}";
    //this->report += "]}";
    
    sgx_thread_mutex_unlock(&g_workload_mutex);
    return this->report;
}

/**
 * @description: serialize workload for sealing
 * @return: serialized workload
 * */
std::string Workload::serialize_workload()
{
    sgx_thread_mutex_lock(&g_workload_mutex);

    std::string plot_data;
    // Store empty_g_hashs
    std::string g_hashs = "{";
    for(auto it=this->empty_g_hashs.begin();it!=this->empty_g_hashs.end();it++)
    {
        g_hashs += std::string(hexstring(*it, HASH_LENGTH)) + ",";
    }
    g_hashs += "}";
    plot_data += g_hashs + ";";
    // Store empty_root_hash
    plot_data += (std::string(hexstring(this->empty_root_hash, sizeof(sgx_sha256_hash_t)))) + ";";
    // Store empty_disk_capacity
    plot_data += (std::to_string(this->empty_disk_capacity)) + ";";
    // Store files
    std::string file_str = "{";
    for(auto it=this->files.begin(); it!=this->files.end(); it++)
    {
        file_str += std::string(hexstring(it->first.data(), it->first.size())) + ":" + std::to_string(it->second)  + ",";
    }
    file_str += "}";
    plot_data += file_str + ";";

    sgx_thread_mutex_unlock(&g_workload_mutex);
    return plot_data;
}

/**
 * @description: Restore workload from serialized workload
 * @return: Restore status
 * */
crust_status_t Workload::restore_workload(std::string plot_data)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    size_t spos=0, epos=0;
    std::string empty_g_hashs_str;
    std::string strbuf;
    uint8_t *empty_root_hash_u = NULL;
    std::string files_str;
    std::string file_entry;
    std::string hash_str;
    size_t hash_size;
    uint8_t *hash_u;
    // Get empty_g_hashs
    for(auto it : this->empty_g_hashs)
    {
        if (it != NULL)
            free(it);
    }
    this->empty_g_hashs.clear(); // Clear current empty_g_hashs
    spos = 0;
    epos = plot_data.find(";");
    if (epos == std::string::npos)
    {
        clean_data();
        return CRUST_BAD_SEAL_DATA;
    }
    empty_g_hashs_str = plot_data.substr(spos,epos);
    empty_g_hashs_str = empty_g_hashs_str.substr(1, empty_g_hashs_str.length()-2);
    while (true)
    {
        epos = empty_g_hashs_str.find(",", spos);
        if((size_t)epos == std::string::npos)
            break;

        strbuf = empty_g_hashs_str.substr(spos, epos-spos);
        uint8_t *g_hash = hex_string_to_bytes(strbuf.c_str(), strbuf.size());
        if (g_hash == NULL)
        {
            clean_data();
            return CRUST_UNEXPECTED_ERROR;
        }
        this->empty_g_hashs.push_back(g_hash);
        spos = epos + 1;
    }
    // Get empty_root_hash
    spos = plot_data.find(";") + 1;
    epos = plot_data.find(";", spos);
    if (epos == std::string::npos)
    {
        clean_data();
        return CRUST_BAD_SEAL_DATA;
    }
    empty_root_hash_u = hex_string_to_bytes(plot_data.substr(spos, epos-spos).c_str(), epos-spos);
    if (empty_root_hash_u == NULL)
    {
        clean_data();
        return CRUST_UNEXPECTED_ERROR;
    }
    memcpy(this->empty_root_hash, empty_root_hash_u, (epos - spos) / 2);
    free(empty_root_hash_u);
    // Get empty_disk_capacity
    spos = epos + 1;
    epos = plot_data.find(";", spos);
    if (epos == std::string::npos)
    {
        clean_data();
        return CRUST_BAD_SEAL_DATA;
    }
    this->empty_disk_capacity = std::stoi(plot_data.substr(spos, epos-spos));
    // Get files
    spos = epos + 1;
    epos = plot_data.find(";", spos);
    if (epos == std::string::npos)
    {
        clean_data();
        return CRUST_BAD_SEAL_DATA;
    }
    files_str = plot_data.substr(spos + 1, epos-spos-1);
    spos = 0;
    while (true)
    {
        epos = files_str.find(",", spos);
        if (epos == std::string::npos)
            break;

        file_entry = files_str.substr(spos, epos-spos);
        spos = epos + 1;
        hash_str = file_entry.substr(0, file_entry.find(":"));
        hash_size = std::stoi(file_entry.substr(file_entry.find(":")+1, file_entry.size()));
        hash_u = hex_string_to_bytes(hash_str.c_str(), hash_str.size());
        if (hash_u == NULL)
        {
            clean_data();
            return CRUST_UNEXPECTED_ERROR;
        }
        this->files.insert(make_pair(std::vector<unsigned char>(hash_u, hash_u + hash_str.size() / 2), hash_size));

        free(hash_u);
    }

    return crust_status;
}
