#include "Enclave.h"

void ecall_main_loop(const char *empty_path)
{
    while (true)
    {
        /* Meaningful */
        Node *diff_files = NULL;
        ocall_get_diff_files(&diff_files);
        size_t diff_files_num = 0;
        ocall_get_diff_files_num(&diff_files_num);
        validate_meaningful_disk(diff_files, diff_files_num);
        /* Empty */
        validate_empty_disk(empty_path);
        /* Show result */
        get_workload()->show();
        ocall_usleep(MAIN_LOOP_WAIT_TIME);
    }
}
