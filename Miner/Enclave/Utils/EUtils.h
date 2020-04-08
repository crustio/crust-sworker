#ifndef _CRUST_E_UTILS_H_
#define _CRUST_E_UTILS_H_

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "Enclave_t.h"

/* The size of a empty disk leaf file */
#define PLOT_RAND_DATA_LENGTH 1048576
//#define PLOT_RAND_DATA_LENGTH 2097152
/* The number of empty disk leaf files under a G path */
#define PLOT_RAND_DATA_NUM 1024
/* Used to store all M hashs under G path */
#define PLOT_M_HASHS "m-hashs.bin"

/* Main loop waiting time (us) */
#define MAIN_LOOP_WAIT_TIME 10000000
#define BUFSIZE 100000
/* The length of hash */
#define HASH_LENGTH 32


#if defined(__cplusplus)
extern "C"
{
#endif

int eprintf(const char* fmt, ...);
int cfeprintf(const char* fmt, ...);
char *hexstring(const void *vsrc, size_t len);
uint8_t *hex_string_to_bytes(const void *src, size_t len);
std::string unsigned_char_array_to_hex_string(const unsigned char *in, size_t size);
std::vector<unsigned char> unsigned_char_array_to_unsigned_char_vector(const unsigned char *in, size_t size);
char* unsigned_char_to_hex(unsigned char in);
crust_status_t seal_data_mrenclave(const uint8_t *p_src, size_t src_len, sgx_sealed_data_t **p_sealed_data, size_t *sealed_data_size);

crust_status_t validate_merkle_tree_c(MerkleTree *root);
bool is_null_hash(unsigned char *hash);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_E_UTILS_H_ */
