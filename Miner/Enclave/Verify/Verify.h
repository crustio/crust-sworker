#ifndef _CRUST_VERIFY_H_
#define _CRUST_VERIFY_H_

#ifndef _WIN32
#include "Resource.h"
#endif
#include "Enclave_t.h"
#include "IASReport.h"
#include "tSgxSSL_api.h"
#include "EUtils.h"
#include <sgx_report.h>
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


#define PSE_RETRIES	        5	/* Arbitrary. Not too long, not too short. */

using namespace std;

string url_decode(string str);
int cert_load_size (X509 **cert, const char *pemdata, size_t sz);
int cert_load (X509 **cert, const char *pemdata);
STACK_OF(X509) * cert_stack_build (X509 **certs);
int cert_verify (X509_STORE *store, STACK_OF(X509) *chain);
void cert_stack_free (STACK_OF(X509) *chain);
int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
    size_t sigsz, EVP_PKEY *pkey, int *result);
X509_STORE * cert_init_ca(X509 *cert);
char *base64_decode(const char *msg, size_t *sz);
ias_status_t verify_iasreport(const char ** IASReport, size_t size, entry_network_signature *p_ensig);

#endif
