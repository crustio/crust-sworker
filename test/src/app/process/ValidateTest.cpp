#include "ValidateTest.h"
#include "ECallsTest.h"

ctpl::thread_pool *g_validate_pool = NULL;
std::vector<std::shared_ptr<std::future<void>>> g_validate_tasks_v;
extern sgx_enclave_id_t global_eid;

void validate_file_test()
{
    if (g_validate_pool == NULL)
    {
        g_validate_pool = new ctpl::thread_pool(Config::get_instance()->srd_thread_num - 2);
    }

    // Push new task
    sgx_enclave_id_t eid = global_eid;
    g_validate_tasks_v.push_back(std::make_shared<std::future<void>>(g_validate_pool->push([eid](int /*id*/){
        Ecall_validate_file_bench_real(eid);
    })));

    // Check and remove complete task
    for (auto it = g_validate_tasks_v.begin(); it != g_validate_tasks_v.end(); )
    {
        if ((*it)->wait_for(std::chrono::seconds(0)) == std::future_status::ready)
        {
            it = g_validate_tasks_v.erase(it);
        }
        else
        {
            it++;
        }
    }
}

void validate_srd_test()
{
    if (g_validate_pool == NULL)
    {
        g_validate_pool = new ctpl::thread_pool(Config::get_instance()->srd_thread_num - 2);
    }

    // Push new task
    sgx_enclave_id_t eid = global_eid;
    g_validate_tasks_v.push_back(std::make_shared<std::future<void>>(g_validate_pool->push([eid](int /*id*/){
        Ecall_validate_srd_bench_real(eid);
    })));

    // Check and remove complete task
    for (auto it = g_validate_tasks_v.begin(); it != g_validate_tasks_v.end(); )
    {
        if ((*it)->wait_for(std::chrono::seconds(0)) == std::future_status::ready)
        {
            it = g_validate_tasks_v.erase(it);
        }
        else
        {
            it++;
        }
    }
}
