#include "Workload.h"

Workload::Workload()
{
    this->empty_disk_capacity = 0;
    for (size_t i = 0; i < 32; i++)
    {
        this->empty_root_hash[i] = 0;
    }
}

Workload::~Workload()
{
    for (size_t i = 0; i < this->empty_g_hashs.size(); i++)
    {
        delete[] this->empty_g_hashs[i];
    }

    this->empty_g_hashs.clear();
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
        eprintf("   Cid->%s, Size->%luB\n", it->first.c_str(), it->second);
    }
}
