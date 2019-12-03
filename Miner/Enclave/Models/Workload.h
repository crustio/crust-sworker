#ifndef _CRUST_WORKLOAD_H_
#define _CRUST_WORKLOAD_H_

#include "../Enclave.h"
#include "../Utils/FormatHelper.h"
#include <vector>
#include <string>
#include <map>
#include "sgx_trts.h"

class Workload
{
public:
    std::vector<unsigned char *> empty_g_hashs;
    sgx_sha256_hash_t empty_root_hash;
    size_t empty_disk_capacity;    
    std::map<std::string, size_t> files;
    Workload();
    ~Workload();
    void show();
};

#endif /* !_CRUST_WORKLOAD_H_ */
