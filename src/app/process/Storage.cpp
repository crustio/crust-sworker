#include "Storage.h"

crust::Log *p_log = crust::Log::get_instance();

extern sgx_enclave_id_t global_eid;

/**
 * @description: Add delete meaningful file task
 * @param cid -> Meaningful file root cid
 */
void storage_add_delete(std::string cid)
{
    sgx_enclave_id_t eid = global_eid;
    std::async(std::launch::async, [eid, cid](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_delete_file(eid, &crust_status, cid.c_str())))
        {
            p_log->err("Delete file failed!Invoke SGX API failed!Error code:%lx\n", sgx_status);
        }
    });
}
