#ifndef _ECALLS_H_
#define _ECALLS_H_

#include <iostream>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <sgx_error.h>
#include <sgx_eid.h>
#include "Enclave_u.h"
#include "Log.h"
#include "CrustStatus.h"
#include "Json.hpp"

// Max thread number.
// Note: If you change this macro name, you should change corresponding name in Makefile
#define ENC_MAX_THREAD_NUM  15
// Reserved enclave resource for highest priority task
#define ENC_RESERVED_THREAD_NUM  1
// Threshold to trigger timeout mechanism
#define ENC_PRIO_TIMEOUT_THRESHOLD 1
// Number of running in enclave permanently
#define ENC_PERMANENT_TASK_NUM 1
// Highest priority
#define ENC_HIGHEST_PRIORITY 0
// Task timeout number
#define ENC_TASK_TIMEOUT  30


#if defined(__cplusplus)
extern "C"
{
#endif

sgx_status_t Ecall_srd_increase(sgx_enclave_id_t eid, const char* path);
sgx_status_t Ecall_srd_decrease(sgx_enclave_id_t eid, size_t *size, size_t change);
sgx_status_t Ecall_srd_update_metadata(sgx_enclave_id_t eid, const char *hashs, size_t hashs_len);
sgx_status_t Ecall_srd_set_change(sgx_enclave_id_t eid, long change);

sgx_status_t Ecall_main_loop(sgx_enclave_id_t eid);
sgx_status_t Ecall_restore_metadata(sgx_enclave_id_t eid, crust_status_t *status);
sgx_status_t Ecall_cmp_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len);
sgx_status_t Ecall_set_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len);
sgx_status_t Ecall_return_validation_status(sgx_enclave_id_t eid, validation_status_t *status);
sgx_status_t Ecall_generate_work_report(sgx_enclave_id_t eid, crust_status_t *status, size_t *report_len);
sgx_status_t Ecall_get_work_report(sgx_enclave_id_t eid, crust_status_t *status, char *report, size_t report_len);

sgx_status_t Ecall_get_signed_work_report(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height,
        sgx_ec256_signature_t *p_signature, char *report, size_t report_len);

sgx_status_t Ecall_sign_network_entry(sgx_enclave_id_t eid, crust_status_t *status, const char *p_partial_data, uint32_t data_size,
        sgx_ec256_signature_t *p_signature);

sgx_status_t Ecall_gen_key_pair(sgx_enclave_id_t eid, sgx_status_t *status);
sgx_status_t Ecall_get_report(sgx_enclave_id_t eid, sgx_status_t *status, sgx_report_t *report, sgx_target_info_t *target_info);
sgx_status_t Ecall_gen_sgx_measurement(sgx_enclave_id_t eid, sgx_status_t *status);

sgx_status_t Ecall_store_quote(sgx_enclave_id_t eid, crust_status_t *status, const char *quote, size_t len, const uint8_t *p_data, uint32_t data_size,
        sgx_ec256_signature_t *p_signature, const uint8_t *p_account_id, uint32_t account_id_sz);

sgx_status_t Ecall_verify_iasreport(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len);

sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *p_tree, size_t tree_len, const char *path,
        char *p_new_path , size_t path_len);

sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, char **files, size_t files_num, const char *p_dir,
        char *p_new_path, uint32_t path_len);

sgx_status_t Ecall_confirm_file(sgx_enclave_id_t eid, const char *hash);

sgx_status_t Ecall_delete_file(sgx_enclave_id_t eid, const char *hash);

sgx_status_t Ecall_get_signed_order_report(sgx_enclave_id_t eid, crust_status_t *status);

sgx_status_t Ecall_id_get_info(sgx_enclave_id_t eid);

sgx_status_t Ecall_get_workload(sgx_enclave_id_t eid);

std::string show_enclave_thread_info();

#if defined(__cplusplus)
}
#endif

#endif /* !_ECALLS_H_ */
