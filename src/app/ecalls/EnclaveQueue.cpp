#include "EnclaveQueue.h"

crust::Log *p_log = crust::Log::get_instance();

EnclaveQueue *EnclaveQueue::enclaveQueue = NULL;

/**
 * @description: Get EnclaveQueue instance
 * @return: Single EnclaveQueue instance
 */
EnclaveQueue *EnclaveQueue::get_instance()
{
    if (EnclaveQueue::enclaveQueue == NULL)
    {
        EnclaveQueue::enclaveQueue = new EnclaveQueue();
    }

    return EnclaveQueue::enclaveQueue;
}

/**
 * @description: Increase waiting queue
 * @param name -> Waiting task name
 */
void EnclaveQueue::increase_waiting_queue(std::string name)
{
    waiting_priority_sum_mutex.lock();
    waiting_priority_sum_v[task_priority_um[name]]++;
    waiting_priority_sum_mutex.unlock();
}

/**
 * @description: Decrease waiting queue
 * @param name -> Waiting task name
 */
void EnclaveQueue::decrease_waiting_queue(std::string name)
{
    SafeLock sl(waiting_priority_sum_mutex);
    sl.lock();
    int priority = task_priority_um[name];
    if (waiting_priority_sum_v[priority] == 0)
    {
        p_log->warn("Priority:%d task sum is 0.\n", priority);
        return;
    }
    waiting_priority_sum_v[priority]--;
}

/**
 * @description: Increase indicated ecall's running number
 * @param name -> Ecall's name
 */
void EnclaveQueue::increase_running_queue(std::string name)
{
    running_ecalls_mutex.lock();
    if (running_ecalls_um.count(name) == 0)
    {
        running_ecalls_um[name] = 0;
    }
    running_ecalls_um[name]++;
    running_ecalls_mutex.unlock();
}

/**
 * @description: Decrease indicated ecall's running number
 * @param name -> Ecall's name
 */
void EnclaveQueue::decrease_running_queue(std::string name)
{
    SafeLock sl(running_ecalls_mutex);
    sl.lock();
    if (running_ecalls_um[name] == 0)
    {
        p_log->warn("Invoking ecall:%s num is 0.\n", name.c_str());
        return;
    }
    running_ecalls_um[name]--;
    sl.unlock();
}

/**
 * @description: Get running tasks total num
 * @return: Running tasks total num
 */
int EnclaveQueue::get_running_ecalls_sum()
{
    running_ecalls_mutex.lock();
    int res = running_task_num;
    running_ecalls_mutex.unlock();

    return res;
}

/**
 * @description: Get running ecalls number
 * @param name -> Running ecall's name
 * @return: Running ecall's number
 */
int EnclaveQueue::get_running_ecalls_num(std::string name)
{
    running_ecalls_mutex.lock();
    int ans = running_ecalls_um[name];
    running_ecalls_mutex.unlock();

    return ans;
}

/**
 * @description: Get running tasks info
 * @return: Running tasks info
 */
std::string EnclaveQueue::get_running_ecalls_info()
{
    running_ecalls_mutex.lock();
    json::JSON info_json;
    for (auto item : running_ecalls_um)
    {
        if (item.second != 0)
        {
            info_json[item.first] = item.second;
        }
    }
    running_ecalls_mutex.unlock();

    return info_json.dump();
}

/**
 * @description: Get higher priority task number
 * @param priority -> current priority
 * @return: The higher task number
 */
int EnclaveQueue::get_higher_prio_waiting_task_num(int priority)
{
    waiting_priority_sum_mutex.lock();
    int ret = 0;
    while (--priority >= 0)
    {
        ret += waiting_priority_sum_v[priority];
    }
    waiting_priority_sum_mutex.unlock();

    return ret;
}

/**
 * @description: Set task sleep by priority
 * @param priority -> Task priority
 */
void EnclaveQueue::task_sleep(int priority)
{
    usleep(task_wait_time_v[priority]);
}

/**
 * @description: Try to get permission to enclave
 * @param name -> Pointer to invoke function name
 * @return: Get status
 */
sgx_status_t EnclaveQueue::try_get_enclave(const char *name)
{
    std::string tname(name);
    std::thread::id tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << tid;
    std::string this_id = ss.str();
    uint32_t timeout = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;

    // Get current task priority
    int cur_task_prio = task_priority_um[tname];
    // Increase corresponding waiting ecall
    increase_waiting_queue(tname);

    // ----- Task scheduling ----- //
    while (true)
    {
        // Check if current task's blocking task is running
        if (block_tasks_um.find(tname) != block_tasks_um.end())
        {
            for (auto btask : block_tasks_um[tname])
            {
                if (get_running_ecalls_num(btask) > 0)
                {
                    goto loop;
                }
            }
        }

        // Following situations cannot get enclave resource:
        // 1. Current task number equal or larger than ENC_MAX_THREAD_NUM
        // 2. Current task priority lower than highest level and remaining resource less than ENC_RESERVED_THREAD_NUM
        // 3. There exists higher priority task waiting
        running_task_num_mutex.lock();
        if (running_task_num >= ENC_MAX_THREAD_NUM 
                || (cur_task_prio > ENC_HIGHEST_PRIORITY && ENC_MAX_THREAD_NUM - running_task_num <= ENC_RESERVED_THREAD_NUM)
                || get_higher_prio_waiting_task_num(cur_task_prio) - ENC_PERMANENT_TASK_NUM > 0)
        {
            running_task_num_mutex.unlock();
            goto loop;
        }
        running_task_num++;
        running_task_num_mutex.unlock();

        // Add current task to running queue and quit
        increase_running_queue(tname);
        break;

    loop:
        // Check if current task is a tiemout task
        if (cur_task_prio > ENC_PRIO_TIMEOUT_THRESHOLD)
        {
            timeout++;
            if (timeout >= ENC_TASK_TIMEOUT)
            {
                //p_log->debug("task:%s(thread id:%s) needs to make way for other tasks.\n", name, this_id.c_str());
                sgx_status = SGX_ERROR_SERVICE_TIMEOUT;
                break;
            }
        }
        task_sleep(cur_task_prio);
    }

    // Decrease corresponding waiting ecall
    decrease_waiting_queue(tname);

    return sgx_status;
}

/**
 * @description: Free enclave
 * @param name -> Pointer to invoke function name
 */
void EnclaveQueue::free_enclave(const char *name)
{
    running_task_num_mutex.lock();
    running_task_num--;
    running_task_num_mutex.unlock();

    decrease_running_queue(name);
}

/**
 * @description: Get blocking upgrade ecalls' number
 * @return: Blocking ecalls' number
 */
int EnclaveQueue::get_upgrade_ecalls_num()
{
    int block_task_num = 0;
    for (auto task : upgrade_blocked_task_us)
    {
        block_task_num += get_running_ecalls_num(task);
    }

    return block_task_num;
}

/**
 * @description: Is there stopping block task running
 * @return: Has or not
 */
bool EnclaveQueue::has_stopping_block_task()
{
    SafeLock sl(running_ecalls_mutex);
    sl.lock();
    for (auto task : this->stop_block_task_v)
    {
        if (running_ecalls_um[task] > 0)
        {
            return true;
        }
    }

    return false;
}
