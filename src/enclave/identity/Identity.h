#ifndef _CRUST_IDENTITY_H_
#define _CRUST_IDENTITY_H_

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
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_ecp_types.h>
#include "sgx_spinlock.h"

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

crust_status_t id_verify_and_upload_identity(char ** IASReport, size_t size);
sgx_status_t id_gen_key_pair(const char *account_id, size_t len);
sgx_status_t id_get_quote_report(sgx_report_t *report, sgx_target_info_t *target_info);
sgx_status_t id_gen_sgx_measurement();
crust_status_t id_cmp_chain_account_id(const char *account_id, size_t len);
void id_get_info();

void id_get_metadata(json::JSON &meta_json, bool locked = true);
/**
 * @description: Set or append metadata responding key
 * @param key -> Indicated key
 * @param val -> Set or append value
 * @param isSet -> Indicate current operation is set or append, default is set
 * @return: Set or append status
 */
template<class T>
crust_status_t id_metadata_set_or_append(const char *key, T val, 
        metadata_op_e op = ID_UPDATE, bool locked = true)
{
    if (locked)
    {
        sgx_thread_mutex_lock(&g_metadata_mutex);
    }

    std::string key_str(key);
    std::string meta_str(SWORKER_PRIVATE_TAG);
    json::JSON meta_json;
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
    meta_str.append(meta_json.dump());
    crust_status = persist_set(ID_METADATA, reinterpret_cast<const uint8_t *>(meta_str.c_str()), meta_str.size());

cleanup:

    if (locked)
    {
        sgx_thread_mutex_unlock(&g_metadata_mutex);
    }

    return crust_status;
}

crust_status_t id_store_metadata();
crust_status_t id_restore_metadata();
crust_status_t id_gen_upgrade_data(size_t block_height);
crust_status_t id_restore_from_upgrade(const char *data, size_t data_size, size_t total_size, bool transfer_end);

#endif
