#ifndef _CRUST_WORKLOAD_TEST_H_
#define _CRUST_WORKLOAD_TEST_H_

#include <utility>
#include <vector>
#include <list>
#include <string>
#include <map>
#include <unordered_map>
#include <set>

#include "sgx_trts.h"
#include "sgx_thread.h"

#include "EUtils.h"
#include "Enclave_t.h"
#include "Persistence.h"
#include "Identity.h"
#include "Srd.h"
#include "Parameter.h"

class WorkloadTest
{
public:
    void test_add_file(long file_num);
    void test_delete_file(uint32_t file_num);
    void test_delete_file_unsafe(uint32_t file_num);
    static WorkloadTest *workloadTest;
    static WorkloadTest *get_instance();

private:
    WorkloadTest() {}
};

#endif /* !_CRUST_WORKLOAD_TEST_H_ */
