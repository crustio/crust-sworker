#include "Validator.h"
#include "ECalls.h"

extern sgx_enclave_id_t global_eid;
Validator *Validator::validator = NULL;
std::mutex validator_mutex;

/**
 * @description: Get validator instance
 * @return: Validator instance
 */
Validator *Validator::get_instance()
{
    if (Validator::validator == NULL)
    {
        validator_mutex.lock();
        if (Validator::validator == NULL)
        {
            Validator::validator = new Validator();
        }
        validator_mutex.unlock();
    }

    return Validator::validator;
}

/**
 * @description: Validator constructor
 */
Validator::Validator()
{
    uint32_t thread_num = std::min(Config::get_instance()->srd_thread_num, VALIDATE_MAX_THREAD_NUM);
    this->validate_pool = new ctpl::thread_pool(thread_num);
}

/**
 * @description: Validate meaningful files
 */
void Validator::validate_file()
{
    // Push new task
    sgx_enclave_id_t eid = global_eid;
    validate_tasks_v.push_back(std::make_shared<std::future<void>>(validate_pool->push([eid](int /*id*/){
        Ecall_validate_file(eid);
    })));

    // Check and remove complete task
    for (auto it = validate_tasks_v.begin(); it != validate_tasks_v.end(); )
    {
        if ((*it)->wait_for(std::chrono::seconds(0)) == std::future_status::ready)
        {
            it = validate_tasks_v.erase(it);
        }
        else
        {
            it++;
        }
    }
}

/**
 * @description: Validate srd
 */
void Validator::validate_srd()
{
    // Push new task
    sgx_enclave_id_t eid = global_eid;
    validate_tasks_v.push_back(std::make_shared<std::future<void>>(validate_pool->push([eid](int /*id*/){
        Ecall_validate_srd(eid);
    })));

    // Check and remove complete task
    for (auto it = validate_tasks_v.begin(); it != validate_tasks_v.end(); )
    {
        if ((*it)->wait_for(std::chrono::seconds(0)) == std::future_status::ready)
        {
            it = validate_tasks_v.erase(it);
        }
        else
        {
            it++;
        }
    }
}
