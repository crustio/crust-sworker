#ifndef _CRUST_UTILS_TEST_H_
#define _CRUST_UTILS_TEST_H_

#include "EUtils.h"
#include "stdbool.h"

#if defined(__cplusplus)
extern "C"
{
#endif

bool test_char_to_int();
bool test_hexstring();
bool test_hexstring_safe();
bool test_hex_string_to_bytes();
bool test_seal_data_mrenclave();
bool test_remove_char();
bool test_base58_encode();
bool test_hash_to_cid();

#if defined(__cplusplus)
}
#endif


#endif /* !_CRUST_UTILS_TEST_H_ */
