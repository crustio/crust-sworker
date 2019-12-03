#include "Enclave.h"

/* 
 * eprintf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int eprintf(const char *fmt, ...)
{
    char buf[100000] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, 100000, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, 100000 - 1) + 1;
}

void ecall_main_loop(const char *empty_path)
{
    
}
