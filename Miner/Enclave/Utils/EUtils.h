#ifndef _CRUST_E_UTILS_H_
#define _CRUST_E_UTILS_H_

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "Enclave_t.h"

/* The size of a empty disk leaf file */
#define PLOT_RAND_DATA_LENGTH 1048576
/* The number of empty disk leaf files under a G path */
#define PLOT_RAND_DATA_NUM 10
/* Used to store all M hashs under G path */
#define PLOT_M_HASHS "m-hashs.bin"

/* Empty disk file verification ratio */
#define EMPTY_VALIDATE_RATE 0.25
/* Meaningful disk file verification ratio */
#define MEANINGFUL_FILE_VALIDATE_RATE 0.10
/* The blocks of meaningful disk file verification ratio */
#define MEANINGFUL_BLOCK_VALIDATE_RATE 0.05

/* Main loop waiting time (us) */
#define MAIN_LOOP_WAIT_TIME 10000000
#define BUFSIZE 10000000
/* The length of hash */
#define HASH_LENGTH 32

/* Crust account id size */
#define CRUST_ACCOUNT_ID_SIZE 32

int eprintf(const char* fmt, ...);
unsigned char *hexstring(const void *vsrc, size_t len);
uint8_t *hex_string_to_bytes(const char *src, size_t len);
uint8_t *concat_bytes(uint8_t *des, size_t *des_len, uint8_t *src, size_t src_len);

#endif /* !_CRUST_E_UTILS_H_ */
