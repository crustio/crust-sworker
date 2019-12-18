#ifndef _CRUST_ENCLAVE_H_
#define _CRUST_ENCLAVE_H_

#ifndef _WIN32
#include "config.h"
#endif
#include "Enclave_t.h"
#include "Enclave.h"
#include "tSgxSSL_api.h"
#include "Verify.h"
#include <string>
#include <vector>

#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_uae_service.h>
#include <sgx_ecp_types.h>
#include "sgx_spinlock.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>

#include "Models/Workload.h"
#include "Utils/EUtils.h"
#include "Validator/Validator.h"
#include "Verify/Verify.h"
#include "ValidationStatus.h"

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

unsigned char offChain_report_data[REPORT_DATA_SIZE] = {'\0'};

sgx_measurement_t current_mr_enclave;

#endif /* !_CRUST_ENCLAVE_H_ */
