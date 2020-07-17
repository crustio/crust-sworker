#ifndef _APP_DATA_H_
#define _APP_DATA_H_

#include <stdio.h>
#include <string>

#if defined(__cplusplus)
extern "C"
{
#endif

std::string get_g_tee_identity();
void set_g_tee_identity(std::string identity);
std::string get_g_order_report();
void set_g_order_report(std::string order_report);
std::string get_g_enclave_id_info();
void set_g_enclave_id_info(std::string id_info);
std::string get_g_enclave_workload();
void set_g_enclave_workload(std::string workload);
std::string get_g_enclave_workreport();
void set_g_enclave_workreport(std::string workreport);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_DATA_H_ */
