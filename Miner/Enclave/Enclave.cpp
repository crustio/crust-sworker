#include "Enclave.h"

void ecall_main_loop(const char *empty_path)
{
    Node *diff_files = NULL;
    ocall_get_diff_files(&diff_files);
    size_t diff_files_num = 0;
    ocall_get_diff_files_num(&diff_files_num);
    ecall_validate_meaningful_disk(diff_files, diff_files_num, diff_files_num * 56);
    ecall_generate_root();
}
