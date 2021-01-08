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
        json::JSON disk_info_json = get_increase_srd_info();
        size_t true_increase = std::min(disk_info_json[WL_DISK_AVAILABLE_FOR_SRD].ToInt(), change);
        // Add left change to next srd, if have
        if (change > (long)true_increase)
        {
            p_log->warn("No enough space for %ldG srd, can only do %ldG srd.\n", change, true_increase);
        }
        if (true_increase == 0)
        {
            //p_log->warn("No available space for srd!\n");
            return false;
        }
        // Print disk info
        p_log->info("Available space is %ldG in '%s' folder, this turn will use %ldG space\n", 
                disk_info_json[WL_DISK_AVAILABLE_FOR_SRD].ToInt(),
                p_config->srd_path.c_str(),
                true_increase);
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);

        // ----- Do srd ----- //
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        ctpl::thread_pool pool(p_config->srd_thread_num);
        std::vector<std::shared_ptr<std::future<sgx_status_t>>> tasks_v;
        for (size_t i = 0; i < true_increase; i++)
        {
            sgx_enclave_id_t eid = global_eid;
            tasks_v.push_back(std::make_shared<std::future<sgx_status_t>>(pool.push([eid](int /*id*/){
                if (SGX_SUCCESS != Ecall_srd_increase_test(eid))
                {
                    // If failed, add current task to next turn
                    crust_status_t crust_status = CRUST_SUCCESS;
                    long real_change = 0;
                    Ecall_change_srd_task(global_eid, &crust_status, 1, &real_change);
                    return SGX_ERROR_UNEXPECTED;
                }
                return SGX_SUCCESS;
            })));
        }
        // Wait for srd task
        size_t srd_success_num = 0;
        for (auto it : tasks_v)
        {
            try 
            {
                if (SGX_SUCCESS == it->get())
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

        if (srd_success_num < true_increase)
        {
            p_log->info("Srd task: %dG, success: %dG, failed: %dG due to timeout or no more disk space.\n", 
                    true_increase, srd_success_num, true_increase - srd_success_num);
        }
        else
        {
            p_log->info("Increase %dG srd files success.\n", true_increase);
        }
    }
    else if (change < 0)
    {
        size_t true_decrease = 0;
        Ecall_srd_decrease_test(global_eid, &true_decrease, (size_t)-change);
        p_log->info("Decrease %luG srd successfully.\n", true_decrease);
    }

    return true;
}
