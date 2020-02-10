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
