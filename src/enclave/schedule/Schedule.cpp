#include "Schedule.h"

sgx_thread_mutex_t g_sched_mutex = SGX_THREAD_MUTEX_INITIALIZER;

// Record executing thread namw
std::map<sched_process_t, int> g_func_m;
// Mapping of task to its block tasks
std::map<sched_process_t, std::set<sched_process_t>> g_block_func_m = {
    {
        SCHED_VALIDATE_SRD,
        {
            SCHED_GET_WORKREPORT,
            SCHED_SRD_CHECK_RESERVED,
        }
    },
    {
        SCHED_VALIDATE_FILE,
        {
            SCHED_GET_WORKREPORT,
            SCHED_GET_ORDERREPORT,
            SCHED_CONFIRM_FILE,
            SCHED_DELETE_FILE,
        }
    },
    {
        SCHED_SRD_CHANGE,
        {
            SCHED_GET_WORKREPORT,
            SCHED_SRD_CHECK_RESERVED,
        }
    },
    {
        SCHED_SRD_CHECK_RESERVED,
        {
            SCHED_GET_WORKREPORT,
        }
    }
};

/**
 * @description: Add executing thread
 * @param id -> Executing thread name
 */
void sched_add(sched_process_t id)
{
    sgx_thread_mutex_lock(&g_sched_mutex);
    g_func_m[id]++;
    sgx_thread_mutex_unlock(&g_sched_mutex);
}

/**
 * @description: Delete executing thread
 * @param id -> Executing thread name
 */
void sched_del(sched_process_t id)
{
    sgx_thread_mutex_lock(&g_sched_mutex);
    g_func_m[id]--;
    sgx_thread_mutex_unlock(&g_sched_mutex);
}

/**
 * @description: Check executing thread
 * @param id -> Executing thread name
 * @param mutex -> Reference to mutex
 */
void sched_check(sched_process_t id, sgx_thread_mutex_t &mutex)
{
    bool release_lock = false;
    sgx_thread_mutex_lock(&g_sched_mutex);
    for (auto proc : g_block_func_m[id])
    {
        if (g_func_m[proc] > 0)
        {
            release_lock = true;
            break;
        }
    }
    sgx_thread_mutex_unlock(&g_sched_mutex);

    if (release_lock)
    {
        sgx_thread_mutex_unlock(&mutex);
        ocall_usleep(1000);
        sgx_thread_mutex_lock(&mutex);
    }
}
