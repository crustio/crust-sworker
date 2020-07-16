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
    std::map<std::string, std::vector<uint8_t*>> srd_path2hashs_m;         /* used to store all G srd file collection' hashs */

    std::vector<json::JSON> checked_files;
    std::vector<json::JSON> new_files;
    std::vector<std::pair<std::string, size_t>> order_files;
    
    static Workload *workload;
    static Workload *get_instance();
    ~Workload();
    std::string get_workload(void);
    json::JSON serialize_srd(bool locked = true);
    crust_status_t restore_srd(json::JSON g_hashs);
    crust_status_t generate_srd_info(sgx_sha256_hash_t *srd_root_out, size_t *srd_workload_out);
    void clean_data();

    void add_new_file(json::JSON file);
    void add_order_file(std::pair<std::string, size_t> file);

    void set_report_flag(bool flag);
    bool get_report_flag();

private:
    // True indicates report files this turn, false means not report
    bool report_files;
};

#endif /* !_CRUST_WORKLOAD_H_ */
