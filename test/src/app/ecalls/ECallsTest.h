#ifndef _ECALLS_TEST_H_
#define _ECALLS_TEST_H_

#include "EnclaveQueue.h"

#if defined(__cplusplus)
extern "C"
{
#endif

sgx_status_t Ecall_add_validate_proof(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_srd_bench(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_srd_test(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_file_bench(sgx_enclave_id_t eid);
sgx_status_t Ecall_store_metadata(sgx_enclave_id_t eid);
sgx_status_t Ecall_srd_increase_test(sgx_enclave_id_t eid);
sgx_status_t Ecall_srd_decrease_test(sgx_enclave_id_t eid, size_t *size, size_t change);
sgx_status_t Ecall_handle_report_result(sgx_enclave_id_t eid);
sgx_status_t Ecall_test_add_file(sgx_enclave_id_t eid, long file_num);
sgx_status_t Ecall_test_delete_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_delete_file_unsafe(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_clean_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_get_file_info(sgx_enclave_id_t eid, crust_status_t *status, const char *data);
sgx_status_t Ecall_gen_upgrade_data_test(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height);
sgx_status_t Ecall_gen_and_upload_work_report_test(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height);
sgx_status_t Ecall_srd_change_test(sgx_enclave_id_t eid, long change, bool real);

#if defined(__cplusplus)
}
#endif

#endif /* !_ECALLS_TEST_H_ */
