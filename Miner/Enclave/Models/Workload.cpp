#include "Workload.h"

Workload::Workload()
{
    empty_disk_capacity = 0;
}

Workload::~Workload()
{
    for (size_t i = 0; i < empty_g_hashs.size(); i++)
    {
        delete[] empty_g_hashs[i];
    }

    empty_g_hashs.clear();
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
    for (auto it = this->files.begin(); it != files.end(); it++)
    {
        eprintf("   Cid->%s, Size->%luB\n", it->first, it->second);
    }
}
