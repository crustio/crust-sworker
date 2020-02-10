#ifndef _CRUST_WORKLOAD_H_
#define _CRUST_WORKLOAD_H_

#include <vector>
#include <string>
#include <map>
#include "sgx_trts.h"
#include "EUtils.h"
#include "FormatHelper.h"

class Workload
{
public:
    std::string report;                                 /* used to store work report */
    std::vector<unsigned char *> empty_g_hashs;         /* used to store all G empty file collection' hashs */
    sgx_sha256_hash_t empty_root_hash;                  /* used to store empty root hash */
    size_t empty_disk_capacity;                         /* empty disk capacity */
    std::map<std::vector<unsigned char>, size_t> files; /* meaningful files' information */

    Workload();
    ~Workload();
    void show(void);
    std::string serialize();
};

Workload *get_workload();

#endif /* !_CRUST_WORKLOAD_H_ */
