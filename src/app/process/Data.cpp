#include "Data.h"
#include "ECalls.h"

// Store sworker identity
std::string g_sworker_identity = "";
// Store enclave identity information
std::string g_enclave_id_info = "";
// Store enclave workload information
std::string g_enclave_workload = "";
// Store signed work report
std::string g_enclave_workreport = "";
// New karst url
std::string g_new_karst_url = "";
// Upgrade data
std::string g_upgrade_data = "";
// Upgrade status
upgrade_status_t g_upgrade_status = UPGRADE_STATUS_NONE;
// Upgrade status mutex
std::mutex g_upgrade_status_mutex;

extern sgx_enclave_id_t global_eid;

std::string get_g_sworker_identity()
{
    return g_sworker_identity;
}

void set_g_sworker_identity(std::string identity)
{
    g_sworker_identity = identity;
}

std::string get_g_enclave_id_info()
{
    return g_enclave_id_info;
}

void set_g_enclave_id_info(std::string id_info)
{
    g_enclave_id_info = id_info;
}

std::string get_g_enclave_workload()
{
    return g_enclave_workload;
}

void set_g_enclave_workload(std::string workload)
{
    g_enclave_workload = workload;
}

std::string get_g_enclave_workreport()
{
    return g_enclave_workreport;
}

void set_g_enclave_workreport(std::string workreport)
{
    g_enclave_workreport = workreport;
}

std::string get_g_new_karst_url()
{
    return g_new_karst_url;
}

void set_g_new_karst_url(std::string karst_url)
{
    g_new_karst_url = karst_url;
}

std::string get_g_upgrade_data()
{
    return g_upgrade_data;
}

void set_g_upgrade_data(std::string data)
{
    g_upgrade_data = data;
}

upgrade_status_t get_g_upgrade_status()
{
    g_upgrade_status_mutex.lock();
    upgrade_status_t status = g_upgrade_status;
    g_upgrade_status_mutex.unlock();

    return status;
}

void set_g_upgrade_status(upgrade_status_t upgrade_status)
{
    g_upgrade_status_mutex.lock();
    g_upgrade_status = upgrade_status;
    switch(g_upgrade_status)
    {
        case UPGRADE_STATUS_NONE:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_NONE\n");
            break;
        case UPGRADE_STATUS_STOP_WORKREPORT:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_STOP_WORKREPORT\n");
            break;
        case UPGRADE_STATUS_PROCESS:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_PROCESS\n");
            break;
        case UPGRADE_STATUS_END:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_END\n");
            break;
        case UPGRADE_STATUS_COMPLETE:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_COMPLETE\n");
            break;
        case UPGRADE_STATUS_EXIT:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_EXIT\n");
            break;
        default:
            p_log->info("Unknown upgrade status!\n");
    }
    g_upgrade_status_mutex.unlock();

    if (UPGRADE_STATUS_NONE == get_g_upgrade_status())
    {
        Ecall_disable_upgrade(global_eid);
    }
}
