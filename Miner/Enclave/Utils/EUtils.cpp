#include "EUtils.h"

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