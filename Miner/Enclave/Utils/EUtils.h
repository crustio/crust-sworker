#ifndef _CRUST_E_UTILS_H_
#define _CRUST_E_UTILS_H_

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "Enclave_t.h" /* print_string */

#define PLOT_RAND_DATA_LENGTH 1048576
#define PLOT_RAND_DATA_NUM 10
#define PLOT_HASH_LENGTH 32

#define EMPTY_VALIDATE_RATE 0.25
#define MEANINGFUL_FILE_VALIDATE_RATE 0.10
#define MEANINGFUL_LEAF_VALIDATE_RATE 0.05

#define MAIN_LOOP_WAIT_TIME 10000000

int eprintf(const char* fmt, ...);

#endif /* !_CRUST_E_UTILS_H_ */
