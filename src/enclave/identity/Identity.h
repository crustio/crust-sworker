#ifndef _CRUST_IDENTITY_H_
#define _CRUST_IDENTITY_H_

#include "Enclave_t.h"
#include "IASReport.h"
#include "tSgxSSL_api.h"
#include "EUtils.h"
#include "EJson.h"
#include "Persistence.h"
#include "Parameter.h"
#include "Defer.h"
#include "sgx_thread.h"
#include <sgx_report.h>
#include <string>
#include <map>
#include <set>
#include <vector>

#include <sgx_utils.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_ecp_types.h>
#include "sgx_spinlock.h"

#define PSE_RETRIES    5    /* Arbitrary. Not too long, not too short. */

enum metadata_op_e
{
    ID_APPEND,
    ID_UPDATE
};

using namespace std;

extern sgx_thread_mutex_t g_metadata_mutex;

string url_decode(string str);
int cert_load_size (X509 **cert, const char *pemdata, size_t sz);
int cert_load (X509 **cert, const char *pemdata);
STACK_OF(X509) * cert_stack_build (X509 **certs);
int cert_verify (X509_STORE *store, STACK_OF(X509) *chain);
void cert_stack_free (STACK_OF(X509) *chain);
int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
    size_t sigsz, EVP_PKEY *pkey, int *result);
X509_STORE * cert_init_ca(X509 *cert);

crust_status_t id_verify_and_upload_identity(char ** IASReport, size_t size);
sgx_status_t id_gen_key_pair(const char *account_id, size_t len);
sgx_status_t id_get_quote_report(sgx_report_t *report, sgx_target_info_t *target_info);
sgx_status_t id_gen_sgx_measurement();
crust_status_t id_cmp_chain_account_id(const char *account_id, size_t len);
void id_get_info();

crust_status_t id_store_metadata();
crust_status_t id_restore_metadata();
crust_status_t id_gen_upgrade_data(size_t block_height);
crust_status_t id_restore_from_upgrade(const char *data, size_t data_size, size_t total_size, bool transfer_end);
size_t id_get_metadata_title_size();
size_t id_get_srd_buffer_size(std::vector<uint8_t *> &srd_hashs);
size_t id_get_file_buffer_size(std::vector<json::JSON> &sealed_files);

#endif
