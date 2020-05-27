#ifndef _CRUST_WORKLOAD_H_
#define _CRUST_WORKLOAD_H_

#include <vector>
#include <string>
#include <map>
#include <set>
#include "sgx_trts.h"
#include "EUtils.h"
#include "Enclave_t.h"
#include "sgx_thread.h"
#include "Persistence.h"
#include "EJson.h"
#include "Identity.h"
#include "Parameter.h"

class Workload
{
public:
    std::vector<unsigned char *> empty_g_hashs;         /* used to store all G empty file collection' hashs */
    json::JSON files_json = json::Array();
    
    static Workload *workload;
    static Workload *get_instance();
    ~Workload();
    void show(void);
    std::string serialize_workload();
    crust_status_t restore_workload(json::JSON g_hashs);
    crust_status_t generate_empty_info(sgx_sha256_hash_t *empty_root_out, size_t *empty_workload_out);
    void clean_data();
    bool reset_meaningful_data();
};

#endif /* !_CRUST_WORKLOAD_H_ */
