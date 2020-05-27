#ifndef _CRUST_FORMAT_UTILS_H_
#define _CRUST_FORMAT_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string>

#ifdef __cplusplus
extern "C"
{
#endif

    int char_to_int(char input);
    uint8_t *hex_string_to_bytes(const char *src, size_t len);
    int from_hexstring(unsigned char *dest, const void *src, size_t len);
    void print_hexstring(const void *vsrc, size_t len);
    char *hexstring(const void *src, size_t len);
    char *hexstring_safe(const void *vsrc, size_t len);
    void remove_char(std::string &data, char c);

    char *base64_encode(const char *msg, size_t sz);
    char *base64_decode(const char *msg, size_t *sz);

#ifdef __cplusplus
};
#endif

#endif /* !_CRUST_FORMAT_UTILS_H_ */
