#ifndef _CRUST_REPORT_H_
#define _CRUST_REPORT_H_

#include <string>
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
#include "Identity.h"
#include "EUtils.h"

# define ERA_LENGTH 300

crust_status_t generate_work_report(size_t *report_len);
crust_status_t get_work_report(char *report, size_t report_len);
crust_status_t get_signed_work_report(const char *block_hash, size_t block_height,
        sgx_ec256_signature_t *p_signature, char *report, size_t report_len);
crust_status_t get_signed_order_report();

void report_change_validated_proof(bool in);
bool report_has_validated_proof();

#endif /* !_CRUST_REPORT_H_ */
