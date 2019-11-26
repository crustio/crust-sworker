#include "Workload.h"

Workload::Workload()
{
    empty_disk_capacity = 0;
}

Workload::~Workload()
{
    for (size_t i = 0; i < all_g_hashs.size(); i++)
    {
        delete[] all_g_hashs[i];
    }

    all_g_hashs.clear();
}
