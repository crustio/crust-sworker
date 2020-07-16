#ifndef _CRUST_IDENTITY_H_
#define _CRUST_IDENTITY_H_

#ifndef _WIN32
#include "Resource.h"
#endif
#include "Enclave_t.h"
#include "IASReport.h"
#include "tSgxSSL_api.h"
#include "EUtils.h"
#include "EJson.h"
#include "Persistence.h"
#include "Parameter.h"
#include "sgx_thread.h"
#include <sgx_report.h>
#include <string>
#include <map>
#include <set>
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


#define PSE_RETRIES	    5	/* Arbitrary. Not too long, not too short. */

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
char *base64_decode(const char *msg, size_t *sz);

crust_status_t id_verify_iasreport(char ** IASReport, size_t size);
sgx_status_t id_gen_key_pair();
sgx_status_t id_get_quote_report(sgx_report_t *report, sgx_target_info_t *target_info);
sgx_status_t id_gen_sgx_measurement();
crust_status_t id_cmp_chain_account_id(const char *account_id, size_t len);
crust_status_t id_set_chain_account_id(const char *account_id, size_t len);
ecc_key_pair id_get_key_pair();
size_t id_get_report_slot();
void id_set_report_slot(size_t new_report_slot);
bool id_just_after_restart();
void id_set_just_after_restart(bool in);
void id_get_info();

void id_get_metadata(json::JSON &meta_json, bool locked = true);
/**
 * @description: Set or append metadata responding key
 * @param key -> Indicated key
 * @param val -> Set or append value
 * @param isSet -> Indicate current operation is set or append, default is set
 * @return: Set or append status
 * */
template<class T>
crust_status_t id_metadata_set_or_append(const char *key, T val, 
        metadata_op_e op = ID_UPDATE, bool locked = true)
{
    if (locked)
    {
        sgx_thread_mutex_lock(&g_metadata_mutex);
    }

    std::string key_str(key);
    std::string meta_str;
    json::JSON meta_json;
    size_t meta_len = 0;
    uint8_t *p_meta = NULL;
    crust_status_t crust_status = CRUST_SUCCESS;
    id_get_metadata(meta_json, false);

    // Check if corresponding entry is set or append
    if (ID_APPEND == op)
    {
        if (meta_json.hasKey(key_str))
        {
            if (meta_json[key_str].JSONType() != json::JSON::Class::Array)
            {
                log_err("Store metadata: key:%s is not a Array!\n", key_str.c_str());
                crust_status = CRUST_UNEXPECTED_ERROR;
                goto cleanup;
            }
            meta_json[key_str].append(val);
        }
        else
        {
            meta_json[key_str][0] = val;
        }
    }
    else if (ID_UPDATE == op)
    {
        meta_json[key_str] = val;
    }
    else
    {
        log_err("Set or append error, unknown operation type!\n");
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    meta_str = meta_json.dump();
    meta_len = meta_str.size() + strlen(TEE_PRIVATE_TAG);
    p_meta = (uint8_t*)enc_malloc(meta_len);
    if (p_meta == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(p_meta, 0, meta_len);
    memcpy(p_meta, TEE_PRIVATE_TAG, strlen(TEE_PRIVATE_TAG));
    memcpy(p_meta + strlen(TEE_PRIVATE_TAG), meta_str.c_str(), meta_str.size());
    crust_status = persist_set(ID_METADATA, p_meta, meta_len);
    free(p_meta);

cleanup:

    if (locked)
    {
        sgx_thread_mutex_unlock(&g_metadata_mutex);
    }

    return crust_status;
}

json::JSON id_metadata_get_by_key(std::string key);
crust_status_t id_metadata_del_by_key(std::string key);
crust_status_t id_metadata_set_by_new(json::JSON meta_json);
crust_status_t id_store_metadata();
crust_status_t id_restore_metadata();

#endif
