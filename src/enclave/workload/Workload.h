#ifndef _CRUST_WORKLOAD_H_
#define _CRUST_WORKLOAD_H_

#include <utility>
#include <vector>
#include <list>
#include <string>
#include <map>
#include <unordered_map>
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
    std::map<std::string, std::vector<uint8_t*>> srd_path2hashs_m;         /* used to store all G empty file collection' hashs */

    std::vector<json::JSON> checked_files;
    std::vector<json::JSON> new_files;
    std::vector<std::pair<std::string, size_t>> order_files;
    
    static Workload *workload;
    static Workload *get_instance();
    ~Workload();
    void show(void);
    std::string serialize_workload(bool locked = true);
    crust_status_t restore_workload(json::JSON g_hashs);
    crust_status_t generate_empty_info(sgx_sha256_hash_t *empty_root_out, size_t *empty_workload_out);
    void clean_data();
    bool reset_meaningful_data();

    void add_new_file(json::JSON file);
    void add_order_file(std::pair<std::string, size_t> file);
};

#endif /* !_CRUST_WORKLOAD_H_ */
