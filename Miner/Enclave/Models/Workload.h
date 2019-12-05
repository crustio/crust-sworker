#ifndef _CRUST_WORKLOAD_H_
#define _CRUST_WORKLOAD_H_

#include <vector>
#include <string>
#include <map>
#include "sgx_trts.h"
#include "../Utils/EUtils.h"
#include "../Utils/FormatHelper.h"

class Workload
{
private:
    char* work;
public:
    std::vector<unsigned char *> empty_g_hashs;
    sgx_sha256_hash_t empty_root_hash;
    size_t empty_disk_capacity;    
    std::map<std::string, size_t> files;
    Workload();
    ~Workload();
    void show();
    char* serialize(const char* block_hash);
};

Workload *get_workload();

#endif /* !_CRUST_WORKLOAD_H_ */
