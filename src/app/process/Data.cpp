#include "Data.h"

// Store TEE identity
std::string g_tee_identity;
// Store order report
std::string g_order_report;
// Store enclave identity information
std::string g_enclave_id_info;
// Store enclave workload information
std::string g_enclave_workload;
// Store signed work report
std::string g_enclave_workreport;

std::string get_g_tee_identity()
{
    return g_tee_identity;
}

void set_g_tee_identity(std::string identity)
{
    g_tee_identity = identity;
}

std::string get_g_order_report()
{
    return g_order_report;
}

void set_g_order_report(std::string order_report)
{
    g_order_report = order_report;
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
