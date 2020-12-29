#include "AsyncTest.h"
#include "ECallsTest.h"

crust::Log *p_log = crust::Log::get_instance();

extern sgx_enclave_id_t global_eid;

/**
 * @description: Add delete meaningful file task
 * @param hash -> Meaningful file root hash
 */
void report_add_callback()
{
    sgx_enclave_id_t eid = global_eid;
    std::async(std::launch::async, [eid](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_handle_report_result(eid)))
        {
            p_log->err("Report result failed!Invoke SGX API failed!Error code:%lx\n", sgx_status);
        }
    });
}
