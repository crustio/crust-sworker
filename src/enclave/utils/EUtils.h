#ifndef _CRUST_E_UTILS_H_
#define _CRUST_E_UTILS_H_

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>

#include "sgx_thread.h"
#include "sgx_trts.h"

#include "Parameter.h"
#include "Enclave_t.h"
#include "Defer.h"

namespace json
{
    class JSON;
}

// Data tag to enclave only data
#define SWORKER_PRIVATE_TAG  "&+CRUSTSWORKERPRIVATE+&"

/* The size of a srd disk leaf file */
#define SRD_RAND_DATA_LENGTH 1048576
//#define SRD_RAND_DATA_LENGTH 2097152
/* The number of srd disk leaf files under a G path */
#define SRD_RAND_DATA_NUM 1024
/* Used to store all M hashs under G path */
#define SRD_M_HASHS "m-hashs.bin"

/* Main loop waiting time (s) */
#define MAIN_LOOP_WAIT_TIME 10
#define LOG_BUF_SIZE 32768 /* 32*1024 */
/* The length of hash */
#define HASH_LENGTH 32

const char *const BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const double base58_ifactor = 1.36565823730976103695740418120764243208481439700722980119458355862779176747360903943915516885072037696111192757109;

typedef sgx_status_t (*p_ocall_store)(const char *data, size_t data_size, bool cover);


#if defined(__cplusplus)
extern "C"
{
#endif

int eprint_info(const char* fmt, ...);
int eprint_debug(const char* fmt, ...);
int log_info(const char* fmt, ...);
int log_warn(const char* fmt, ...);
int log_err(const char* fmt, ...);
int log_debug(const char* fmt, ...);
int char_to_int(char input);
char *hexstring(const void *vsrc, size_t len);
std::string hexstring_safe(const void *vsrc, size_t len);
uint8_t *hex_string_to_bytes(const void *src, size_t len);
std::string unsigned_char_array_to_hex_string(const unsigned char *in, size_t size);
std::vector<unsigned char> unsigned_char_array_to_unsigned_char_vector(const unsigned char *in, size_t size);
char* unsigned_char_to_hex(unsigned char in);
std::string byte_vec_to_string(std::vector<uint8_t> bytes);

sgx_status_t Sgx_seal_data(const uint32_t additional_MACtext_length,
                           const uint8_t *p_additional_MACtext, const uint32_t text2encrypt_length,
                           const uint8_t *p_text2encrypt, const uint32_t sealed_data_size,
                           sgx_sealed_data_t *p_sealed_data);

sgx_status_t Sgx_seal_data_ex(const uint16_t key_policy,
                              const sgx_attributes_t attribute_mask,
                              const sgx_misc_select_t misc_mask,
                              const uint32_t additional_MACtext_length,
                              const uint8_t *p_additional_MACtext, const uint32_t text2encrypt_length,
                              const uint8_t *p_text2encrypt, const uint32_t sealed_data_size,
                              sgx_sealed_data_t *p_sealed_data);

crust_status_t seal_data_mrenclave(const uint8_t *p_src, size_t src_len, sgx_sealed_data_t **p_sealed_data, size_t *sealed_data_size);
crust_status_t seal_data_mrsigner(const uint8_t *p_src, size_t src_len, sgx_sealed_data_t **p_sealed_data, size_t *sealed_data_size);
crust_status_t unseal_data_mrsigner(const sgx_sealed_data_t *data, uint8_t **p_decrypted_data, uint32_t *decrypted_data_len);

crust_status_t validate_merkletree_json(json::JSON tree);
void *enc_malloc(size_t size);
void *enc_realloc(void *p, size_t size);
void *enc_crealloc(void *p, size_t old_size, size_t new_size);
void remove_char(std::string &data, char c);
void replace(std::string &data, std::string org_str, std::string det_str);
void store_large_data(const uint8_t *data, size_t data_size, p_ocall_store p_func, sgx_thread_mutex_t &mutex);
char *base64_decode(const char *msg, size_t *sz);
std::string base58_encode(const uint8_t *input, size_t len);
std::string hash_to_cid(const uint8_t *hash);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_E_UTILS_H_ */
