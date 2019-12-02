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
