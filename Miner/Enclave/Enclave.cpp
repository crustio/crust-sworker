#include "Enclave.h"

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
size_t ecall_(const char *block_hash)
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
