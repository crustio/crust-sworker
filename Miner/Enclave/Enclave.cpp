#include "Enclave.h"

using namespace std;

/* Used to store validation status */
enum ValidationStatus validation_status = ValidateStop;

/**
 * @description: ecall main loop
 * @param empty_path -> the empty directory path
 */
void ecall_main_loop(const char *empty_path)
{
    ecall_generate_empty_root();
    
    while (true)
    {
        eprintf("\n-----Meaningful Validation-----\n");
        /* Meaningful */
        validation_status = ValidateMeaningful;
        Node *diff_files = NULL;
        ocall_get_diff_files(&diff_files);
        size_t diff_files_num = 0;
        ocall_get_diff_files_num(&diff_files_num);
        validate_meaningful_disk(diff_files, diff_files_num);

        eprintf("\n-----Empty Validation-----\n");
        /* Empty */
        validation_status = ValidateEmpty;
        validate_empty_disk(empty_path);

        eprintf("\n-----Validation Waiting-----\n");
        /* Show result */
        validation_status = ValidateWaiting;
        get_workload()->show();
        ocall_usleep(MAIN_LOOP_WAIT_TIME);
    }
}

/**
 * @description: return validation status
 * @return: the validation status
 */
enum ValidationStatus ecall_return_validation_status(void)
{
    return validation_status;
}

/**
 * @description: generate validation report
 * @param block_hash -> used to generate validation report
 * @return: the length of validation report
 */
size_t ecall_generate_validation_report(const char *block_hash)
{
    return get_workload()->serialize(block_hash).size() + 1;
}

/**
 * @description: get validation report
 * @param report(out) -> the validation report
 * @param len -> the length of validation report
 * @return: the validation report
 */
void ecall_get_validation_report(char *report, size_t len)
{
    std::copy(get_workload()->report.begin(), get_workload()->report.end(), report);
    report[len - 1] = '\0';
}

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t ecall_get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
    // generate public and private key
    sgx_ec256_public_t pub_key;
    sgx_ec256_private_t pri_key;
    memset(&pub_key, 0, sizeof(pub_key));
    memset(&pri_key, 0, sizeof(pri_key));
    sgx_status_t se_ret;
    sgx_ecc_state_handle_t ecc_state = NULL;
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if(SGX_SUCCESS != se_ret) {
        return se_ret;
    }
    se_ret = sgx_ecc256_create_key_pair(&pri_key, &pub_key, ecc_state);
    if(SGX_SUCCESS != se_ret) {
        return se_ret;
    }
    if(ecc_state != NULL) {
        sgx_ecc256_close_context(ecc_state);
    }
    // copy public key to report data
    sgx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    memcpy(&report_data, &pub_key, sizeof(pub_key));
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, &report_data, report);
#else
	return sgx_create_report(target_info, &report_data, report);
#endif
}

sgx_status_t ecall_store_quote(const char *quote, int len)
{
    sgx_quote_t *offChain_quote = (sgx_quote_t*)malloc(len);
    memset(offChain_quote, 0, len);
    memcpy(offChain_quote, quote, len);
    unsigned char *p_report_data = offChain_quote->report_body.report_data.d;
    memcpy(offChain_report_data, p_report_data, REPORT_DATA_SIZE);
}

ias_status_t ecall_verify_iasreport(const char ** IASReport, int len) 
{
    return ecall_verify_iasreport_real(IASReport, len);
}
