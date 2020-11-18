#ifndef _CRUST_MAIN_TEST_H_
#define _CRUST_MAIN_TEST_H_

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sgx_urts.h>
#include <sgx_error.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include "Enclave_u.h"

#define ENCLAVE_TEST_FILE_PATH   "src/enclave.signed.so"

#if defined(__cplusplus)
extern "C"
{
#endif

int test_enclave();

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_MAIN_TEST_H_ */
