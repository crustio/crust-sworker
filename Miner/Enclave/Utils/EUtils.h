#ifndef _CRUST_E_UTILS_H_
#define _CRUST_E_UTILS_H_

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "Enclave_t.h" /* print_string */

#if defined(__cplusplus)
extern "C" {
#endif

int eprintf(const char* fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_E_UTILS_H_ */
