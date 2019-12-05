#include "Workload.h"

Workload *workload = new Workload();

Workload *get_workload()
{
    return workload;
}

Workload::Workload()
{
    this->empty_disk_capacity = 0;
    for (size_t i = 0; i < 32; i++)
    {
        this->empty_root_hash[i] = 0;
    }
    this->work = NULL;
}

Workload::~Workload()
{
    for (size_t i = 0; i < this->empty_g_hashs.size(); i++)
    {
        delete[] this->empty_g_hashs[i];
    }

    this->empty_g_hashs.clear();

    if (this->work != NULL)
    {
        delete[] this->work;
        this->work = NULL;
    }
}

void Workload::show()
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
        eprintf("Cid->%s, Size->%luB\n", it->first.c_str(), it->second);
    }
}

char *Workload::serialize(const char *block_hash)
{
    std::string result = "{";
    result += "'block_hash':'" + std::string(block_hash) + "',";
    result += "'empty_root_hash':'" + unsigned_char_array_to_hex_string(this->empty_root_hash, PLOT_HASH_LENGTH) + "',";
    result += "'empty_disk_capacity':" + std::to_string(this->empty_disk_capacity) + ",";
    result += "files:[";
    for (auto it = this->files.begin(); it != this->files.end(); it++)
    {
        result += "{'cid':'" + it->first + "','size':" + std::to_string(it->second) + "},";
    }
    result += "]}";

    if (this->work != NULL)
    {
        delete[] this->work;
        this->work = NULL;
    }

    this->work = new char[result.size() + 1];
    std::copy(result.begin(), result.end(), this->work);
    this->work[result.size()] = '\0';
    return this->work;
}
