#ifndef _CRUST_FORMAT_UTILS_H_
#define _CRUST_FORMAT_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

int char_to_int(char input);
void hex_string_to_bytes(const char *src, unsigned char *target);
int from_hexstring(unsigned char *dest, const void *src, size_t len);
void print_hexstring (FILE *fp, const void *vsrc, size_t len);
char *hexstring(const void *src, size_t len);

char *base64_encode(const char *msg, size_t sz);
char *base64_decode(const char *msg, size_t *sz);

static char *_hex_buffer= NULL;
static size_t _hex_buffer_size= 0;
const char _hextable[]= "0123456789abcdef";

#ifdef __cplusplus
};
#endif

#endif /* !_CRUST_FORMAT_UTILS_H_ */
