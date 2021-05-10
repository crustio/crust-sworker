#include "SrdTest.h"
#include "Srd.h"
#include "ECalls.h"
#include "ECallsTest.h"
#include "Ctpl.h"

crust::Log *p_log = crust::Log::get_instance();

extern sgx_enclave_id_t global_eid;

bool srd_change_test(long change)
{
    Config *p_config = Config::get_instance();

    if (change > 0)
    {
        long left_task = change;
        json::JSON disk_info_json = get_increase_srd_info(left_task);
        long true_increase = change - left_task;
        // Print disk info
        for (auto info : disk_info_json.ArrayRange())
        {
            if (info[WL_DISK_USE].ToInt() > 0)
            {
                p_log->info("Available space is %ldG in '%s', this turn will use %ldG space\n", 
                        info[WL_DISK_AVAILABLE_FOR_SRD].ToInt(),
                        info[WL_DISK_PATH].ToString().c_str(),
                        info[WL_DISK_USE].ToInt());
            }
        }
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);

        // ----- Do srd ----- //
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        ctpl::thread_pool pool(p_config->srd_thread_num);
        std::vector<std::shared_ptr<std::future<crust_status_t>>> tasks_v;
        long task = true_increase;
        while (task > 0)
        {
            for (int i = 0; i < disk_info_json.size() && task > 0; i++, task--)
            {
                sgx_enclave_id_t eid = global_eid;
                std::string uuid = disk_info_json[i][WL_DISK_UUID].ToString();
                tasks_v.push_back(std::make_shared<std::future<crust_status_t>>(pool.push([&eid, uuid](int /*id*/){
                    sgx_status_t sgx_status = SGX_SUCCESS;
                    crust_status_t increase_ret = CRUST_SUCCESS;
                    if (SGX_SUCCESS != (sgx_status = Ecall_srd_increase_test(eid, &increase_ret, uuid.c_str()))
                            || CRUST_SUCCESS != increase_ret)
                    {
                        // If failed, add current task to next turn
                        long real_change = 0;
                        crust_status_t change_ret = CRUST_SUCCESS;
                        Ecall_change_srd_task(global_eid, &change_ret, 1, &real_change);
                        sgx_status = SGX_ERROR_UNEXPECTED;
                    }
                    if (SGX_SUCCESS != sgx_status)
                    {
                        increase_ret = CRUST_UNEXPECTED_ERROR;
                    }
                    decrease_running_srd_task();
                    return increase_ret;
                })));
            }
        }
        // Wait for srd task
        long srd_success_num = 0;
        for (auto it : tasks_v)
        {
            try 
            {
                if (CRUST_SUCCESS == it->get())
                {
                    srd_success_num++;
                }
            }
            catch (std::exception &e)
            {
                p_log->err("Catch exception:");
                std::cout << e.what() << std::endl;
            }
        }
        
        if (srd_success_num == 0)
        {
            return false;
        }

        if (srd_success_num < change)
        {
            p_log->info("Srd task: %dG, success: %dG, failed: %dG due to timeout or no more disk space.\n", 
                    change, srd_success_num, change - srd_success_num);
        }
        else
        {
            p_log->info("Increase %dG srd files success.\n", change);
        }
    }
    else if (change < 0)
    {
        size_t true_decrease = 0;
        sgx_status_t sgx_status = SGX_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_srd_decrease_test(global_eid, &true_decrease, (size_t)-change)))
        {
            p_log->err("Decrease %ldG srd failed! Error code:%lx\n", change, sgx_status);
        }
        else
        {
            p_log->info("Decrease %luG srd successfully.\n", true_decrease);
        }
    }

    return true;
}
