#include "Storage.h"

crust::Log *p_log = crust::Log::get_instance();

extern sgx_enclave_id_t global_eid;

/**
 * @description: Add confirm meaningful file task
 * @param hash -> Meaningful file root hash
 */
void storage_add_confirm(std::string hash)
{
    sgx_enclave_id_t eid = global_eid;
    std::async(std::launch::async, [eid, hash](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_confirm_file(eid, &crust_status, hash.c_str())))
        {
            p_log->err("Confirm new file failed!Invoke SGX API failed!Error code:%lx\n", sgx_status);
        }
    });
}

/**
 * @description: Add delete meaningful file task
 * @param hash -> Meaningful file root hash
 */
void storage_add_delete(std::string hash)
{
    sgx_enclave_id_t eid = global_eid;
    std::async(std::launch::async, [eid, hash](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_delete_file(eid, &crust_status, hash.c_str())))
        {
            p_log->err("Delete file failed!Invoke SGX API failed!Error code:%lx\n", sgx_status);
        }
    });
}

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
