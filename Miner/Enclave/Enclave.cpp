#include "Enclave.h"

enum ValidationStatus validation_status = ValidateWaiting;

void ecall_main_loop(const char *empty_path)
{
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

enum ValidationStatus ecall_return_validation_status()
{
    return validation_status;
}

char *ecall_get_validation_report(const char *block_hash)
{
    return get_workload()->serialize(block_hash);
}
