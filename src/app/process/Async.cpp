#include "Async.h"
#include "ECalls.h"

void clean_complete_task();

crust::Log *p_log = crust::Log::get_instance();

extern sgx_enclave_id_t global_eid;

std::vector<std::future<void>> storage_task_v;

/**
 * @description: Add delete meaningful file task
 * @param cid -> Meaningful file root cid
 */
void async_storage_delete(std::string cid)
{
    sgx_enclave_id_t eid = global_eid;
    storage_task_v.push_back(std::async(std::launch::async, [eid, cid](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_delete_file(eid, &crust_status, cid.c_str())))
        {
            p_log->err("Delete file(%s) failed!Invoke SGX API failed!Error code:%lx\n", cid.c_str(), sgx_status);
        }
        else if (CRUST_SUCCESS != crust_status)
        {
            p_log->err("Delete file(%s) failed!Error code:%lx\n", cid.c_str(), crust_status);
        }
        EnclaveData::get_instance()->del_sealed_file_info(cid);
        p_log->info("Delete file(%s) successfully!\n", cid.c_str());
    }));
    clean_complete_task();
}

/**
 * @description: Add seal meaningful file task
 * @param cid -> Meaningful file root cid
 */
void async_storage_seal(std::string cid)
{
    sgx_enclave_id_t eid = global_eid;
    storage_task_v.push_back(std::async(std::launch::async, [eid, cid](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_seal_file(eid, &crust_status, cid.c_str())))
        {
            p_log->err("Seal file(%s) failed!Invoke SGX API failed!Error code:%lx\n", cid.c_str(), sgx_status);
        }
        else if (CRUST_SUCCESS != crust_status)
        {
            switch (crust_status)
            {
            case CRUST_SEAL_DATA_FAILED:
                p_log->err("Seal file(%s) failed!Internal error: seal data failed!\n", cid.c_str());
                break;
            case CRUST_FILE_NUMBER_EXCEED:
                p_log->err("Seal file(%s) failed!No more file can be sealed!File number reachs the upper limit!\n", cid.c_str());
                break;
            case CRUST_UPGRADE_IS_UPGRADING:
                p_log->err("Seal file(%s) failed due to upgrade!\n", cid.c_str());
                break;
            case CRUST_STORAGE_FILE_DUP:
                p_log->err("Seal file(%s) failed!This file has been sealed.\n", cid.c_str());
                break;
            default:
                p_log->err("Seal file(%s) failed!Unexpected error!\n", cid.c_str());
            }
        }
        else
        {
            p_log->info("Seal file(%s) successfully!\n", cid.c_str());
        }
    }));
    clean_complete_task();
}

/**
 * @description: Clean completed tasks
 */
void clean_complete_task()
{
    std::future_status f_status;
    for (auto it = storage_task_v.begin(); it != storage_task_v.end();)
    {
        f_status = it->wait_for(std::chrono::seconds(0));
        if (f_status == std::future_status::ready)
        {
            it = storage_task_v.erase(it);
        }
        else
        {
            it++;
        }
    }
}
