#include "Storage.h"
#include "ECalls.h"

crust::Log *p_log = crust::Log::get_instance();

extern sgx_enclave_id_t global_eid;

/**
 * @description: Do real new file confirmation
 * @param hash -> Pointer to new file root hash
 * */
void storage_confirm_file(const char *hash)
{
    sgx_enclave_id_t eid = global_eid;
    crust::Log *p_log_r = p_log;
    std::string hash_str(hash);
    std::thread thread_confirm([eid, hash_str, p_log_r](void){
        crust_status_t crust_status = CRUST_SUCCESS;
        sgx_status_t sgx_status = SGX_SUCCESS;
        std::string res_info;
        if (SGX_SUCCESS != (sgx_status = Ecall_confirm_file_real(eid, &crust_status, hash_str.c_str()))
                || CRUST_SUCCESS != crust_status)
        {
            res_info = "Confirm new file failed!";
            if (SGX_SUCCESS != sgx_status)
            {
                p_log_r->err("%s(SGX error)Error code:%lx\n", res_info.c_str(), sgx_status);
            }
            else
            {
                p_log_r->err("%sError code:%lx\n", res_info.c_str(), crust_status);
            }
        }
        else
        {
            res_info = "Confirm new file successfully!";
            p_log_r->info("%s\n", res_info.c_str());
        }
    });
    thread_confirm.detach();
}
