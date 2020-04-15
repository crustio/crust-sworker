#ifndef _CRUST_ENCLAVE_H_
#define _CRUST_ENCLAVE_H_

#ifndef _WIN32
#include "Resource.h"
#endif
#include "Enclave_t.h"
#include "tSgxSSL_api.h"
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

#include "Workload.h"
#include "EUtils.h"
#include "Validator.h"
#include "ValidationStatus.h"
#include "Srd.h"
#include "Report.h"

#endif /* !_CRUST_ENCLAVE_H_ */
