#ifndef _ECALLS_H_
#define _ECALLS_H_

#include "EnclaveQueue.h"

#if defined(__cplusplus)
extern "C"
{
#endif

sgx_status_t Ecall_srd_increase(sgx_enclave_id_t eid, crust_status_t *status, const char *uuid);
sgx_status_t Ecall_srd_decrease(sgx_enclave_id_t eid, size_t *size, size_t change);
sgx_status_t Ecall_srd_remove_space(sgx_enclave_id_t eid, const char *data, size_t data_size);
sgx_status_t Ecall_change_srd_task(sgx_enclave_id_t eid, crust_status_t *status, long change, long *real_change);

sgx_status_t Ecall_main_loop(sgx_enclave_id_t eid);
sgx_status_t Ecall_stop_all(sgx_enclave_id_t eid);
sgx_status_t Ecall_restore_metadata(sgx_enclave_id_t eid, crust_status_t *status);
sgx_status_t Ecall_cmp_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len);
sgx_status_t Ecall_gen_and_upload_work_report(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height);

sgx_status_t Ecall_gen_key_pair(sgx_enclave_id_t eid, sgx_status_t *status, const char *account_id, size_t len);
sgx_status_t Ecall_get_quote_report(sgx_enclave_id_t eid, sgx_status_t *status, sgx_report_t *report, sgx_target_info_t *target_info);
sgx_status_t Ecall_gen_sgx_measurement(sgx_enclave_id_t eid, sgx_status_t *status);

sgx_status_t Ecall_verify_and_upload_identity(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len);

sgx_status_t Ecall_seal_file_start(sgx_enclave_id_t eid, crust_status_t *status, const char *cid, const char *cid_b58);

sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *cid, const uint8_t *data, size_t data_size, bool is_link, char *path, size_t path_size);

sgx_status_t Ecall_seal_file_end(sgx_enclave_id_t eid, crust_status_t *status, const char *cid);

sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *path, uint8_t *p_decrypted_data, size_t decrypted_data_size, size_t *p_decrypted_data_size);

sgx_status_t Ecall_delete_file(sgx_enclave_id_t eid, crust_status_t *status, const char *hash);

sgx_status_t Ecall_id_get_info(sgx_enclave_id_t eid);
sgx_status_t Ecall_recover_illegal_file(sgx_enclave_id_t eid, crust_status_t *status, const uint8_t *data, size_t data_size);

sgx_status_t Ecall_enable_upgrade(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height);
sgx_status_t Ecall_disable_upgrade(sgx_enclave_id_t eid);
sgx_status_t Ecall_gen_upgrade_data(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height);
sgx_status_t Ecall_restore_from_upgrade(sgx_enclave_id_t eid, crust_status_t *status, const uint8_t *data, size_t data_size);

sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid);

sgx_status_t Ecall_safe_store2(sgx_enclave_id_t eid, crust_status_t *status, ecall_store_type_t f, const uint8_t *data, size_t total_size, size_t partial_size, size_t offset, uint32_t buffer_key);

#if defined(__cplusplus)
}
#endif

#endif /* !_ECALLS_H_ */
