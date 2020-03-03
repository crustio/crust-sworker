#include "Workload.h"

extern ecc_key_pair id_key_pair;
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
    eprintf("Empty root hash: \n");
    for (size_t i = 0; i < 32; i++)
    {
        eprintf("%02x", this->empty_root_hash[i]);
    }
    eprintf("\n");
    eprintf("Empty capacity: %luG\n", this->empty_disk_capacity);

    eprintf("Meaningful work is: \n");
    for (auto it = this->files.begin(); it != this->files.end(); it++)
    {
        eprintf("Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_char_array(it->first.data(), HASH_LENGTH), it->second);
    }
}

/**
 * @description: use block hash to serialize work report
 * @return: the work report
 */
std::string Workload::serialize()
{
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

    return this->report;
}

std::string Workload::serialize_workload()
{
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

    return plot_data;
}

validate_status_t Workload::restore_workload(std::string plot_data)
{
    validate_status_t validate_status = VALIDATION_SUCCESS;
    int spos=0, epos=0;
    std::string empty_g_hashs_str;
    std::string strbuf;
    uint8_t *empty_root_hash_u;
    std::string files_str;
    std::string file_entry;
    std::string hash_str;
    size_t hash_size;
    uint8_t *hash_u;
    // Get empty_g_hashs
    this->empty_g_hashs.clear(); // Clear current empty_g_hashs
    spos = 0;
    epos = plot_data.find(";");
    empty_g_hashs_str = plot_data.substr(spos,epos);
    empty_g_hashs_str = empty_g_hashs_str.substr(1, empty_g_hashs_str.length()-2);
    while (true)
    {
        epos = empty_g_hashs_str.find(",", spos);
        if((size_t)epos == std::string::npos)
        {
            break;
        }
        strbuf = empty_g_hashs_str.substr(spos, epos-spos);
        this->empty_g_hashs.push_back(hex_string_to_bytes(strbuf.c_str(), strbuf.size()));
        spos = epos + 1;
    }
    // Get empty_root_hash
    spos = plot_data.find(";") + 1;
    epos = plot_data.find(";", spos);
    empty_root_hash_u = hex_string_to_bytes(plot_data.substr(spos, epos-spos).c_str(), epos-spos);
    if (empty_root_hash_u == NULL)
    {
        return VALIDATION_INVALID_ROOT_HASH;
    }
    memcpy(this->empty_root_hash, empty_root_hash_u, (epos - spos) / 2);
    // Get empty_disk_capacity
    spos = epos + 1;
    epos = plot_data.find(";", spos);
    this->empty_disk_capacity = std::stoi(plot_data.substr(spos, epos-spos));
    // Get files
    spos = epos + 1;
    epos = plot_data.find(";", spos);
    files_str = plot_data.substr(spos + 1, epos-spos-1);
    spos = 0;
    while (true)
    {
        epos = files_str.find(",", spos);
        if ((size_t)epos == std::string::npos)
        {
            break;
        }
        file_entry = files_str.substr(spos, epos-spos);
        spos = epos + 1;
        hash_str = file_entry.substr(0, file_entry.find(":"));
        hash_size = std::stoi(file_entry.substr(file_entry.find(":")+1, file_entry.size()));
        hash_u = hex_string_to_bytes(hash_str.c_str(), hash_str.size());
        this->files.insert(make_pair(std::vector<unsigned char>(hash_u, hash_u + hash_str.size() / 2), hash_size));
    }

    return validate_status;
}

/**
 * @description: Store plot workload to file
 * @return: Store status
 * */
validate_status_t Workload::store_plot_data()
{
    std::string plot_data = serialize_workload();
    
    // Seal workload string
    sgx_status_t sgx_status = SGX_SUCCESS;
    validate_status_t validate_status = VALIDATION_SUCCESS;
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, plot_data.size());
    sgx_sealed_data_t *p_sealed_data = (sgx_sealed_data_t*)malloc(sealed_data_size);
    memset(p_sealed_data, 0, sealed_data_size);
    sgx_attributes_t sgx_attr;
    sgx_attr.flags = 0xFF0000000000000B;
    sgx_attr.xfrm = 0;
    sgx_misc_select_t sgx_misc = 0xF0000000;
    sgx_status = sgx_seal_data_ex(0x0001,
                                  sgx_attr,
                                  sgx_misc,
                                  0,
                                  NULL,
                                  plot_data.size(),
                                  (const uint8_t*)plot_data.c_str(),
                                  sealed_data_size,
                                  p_sealed_data);
    if (SGX_SUCCESS != sgx_status)
    {
        validate_status =  VALIDATION_SEAL_DATA_FAILED;
        goto cleanup;
    }

    //eprintf("==========[enclave] sealed data:%s\n", hexstring(p_sealed_data, sealed_data_size));

    // Store sealed data to file
    if (SGX_SUCCESS != ocall_store_plot_data(&validate_status, p_sealed_data, sealed_data_size))
    {
        validate_status = VALIDATION_STORE_PLOT_DATA_FAILED;
        goto cleanup;
    }


cleanup:
    free(p_sealed_data);

    return validate_status;
}

/**
 * @description: Get workload from file
 * @return: Get status
 * */
validate_status_t Workload::get_plot_data()
{
    sgx_sealed_data_t *p_sealed_data;
    validate_status_t validate_status = VALIDATION_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    uint32_t sealed_data_size;
    std::string plot_data;
    /* Unseal data */
    // Get sealed data from file
    if (SGX_SUCCESS != ocall_get_plot_data(&validate_status, &p_sealed_data, &sealed_data_size))
    {
        validate_status = VALIDATION_GET_PLOT_DATA_FAILED;
        return validate_status;
    }
    // Create buffer in enclave
    sgx_sealed_data_t *p_sealed_data_r = (sgx_sealed_data_t*)malloc(sealed_data_size);
    memset(p_sealed_data_r, 0, sealed_data_size);
    memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
    // Create buffer for decrypted data
    uint32_t decrypted_data_len = sgx_get_encrypt_txt_len(p_sealed_data_r);
    sgx_sealed_data_t *p_decrypted_data = (sgx_sealed_data_t*)malloc(decrypted_data_len);
    // Unseal sealed data
    sgx_status = sgx_unseal_data(p_sealed_data_r,
                                 NULL,
                                 NULL,
                                 (uint8_t*)p_decrypted_data,
                                 &decrypted_data_len);
    if (SGX_SUCCESS != sgx_status)
    {
        validate_status = VALIDATION_UNSEAL_DATA_FAILED;
        eprintf("===========[enclave] get plot data failed:%lx\n", sgx_status);
        goto cleanup;
    }
    plot_data = std::string((const char*)p_decrypted_data, decrypted_data_len);
    eprintf("===========[enclave] get plot data:%s\n", plot_data.c_str());

    restore_workload(plot_data);


cleanup:

    free(p_sealed_data_r);
    free(p_decrypted_data);

    return validate_status;
}
