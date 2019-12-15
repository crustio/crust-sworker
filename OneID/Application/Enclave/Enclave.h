#ifndef __ENCLAVE_QUOTE_H
#define __ENCLAVE_QUOTE_H

#define IAS_MK_ERROR(x)              (0x00000000|(x))


typedef enum _ra_state
{
    ra_inited= 0,
    ra_get_gaed,
    ra_proc_msg2ed
} ra_state;

typedef enum _ias_status_t
{
    IAS_QUERY_FAILED        = IAS_MK_ERROR(0),
    IAS_OK                  = IAS_MK_ERROR(200),
    IAS_VERIFY_SUCCESS      = IAS_MK_ERROR(2000),
    IAS_VERIFY_FAILED       = IAS_MK_ERROR(2001),
    IAS_BADREQUEST          = IAS_MK_ERROR(400),
    IAS_UNAUTHORIZED        = IAS_MK_ERROR(401),
    IAS_NOT_FOUND           = IAS_MK_ERROR(404),
    IAS_SERVER_ERR          = IAS_MK_ERROR(500),
    IAS_UNAVAILABLE         = IAS_MK_ERROR(503),
    IAS_INTERNAL_ERROR      = IAS_MK_ERROR(1000),
    IAS_BAD_CERTIFICATE     = IAS_MK_ERROR(1001),
    IAS_BAD_SIGNATURE       = IAS_MK_ERROR(1002),
    IAS_REPORTDATA_NE       = IAS_MK_ERROR(1003),
    IAS_GET_REPORT_FAILED   = IAS_MK_ERROR(1004),
    IAS_BADMEASUREMENT      = IAS_MK_ERROR(1005),
    IAS_GETPUBKEY_FAILED    = IAS_MK_ERROR(1006),
} ias_status_t;

/*typedef struct _ra_db_item_t
{
    sgx_ec256_public_t          g_a;
    sgx_ec256_public_t          g_b;
    sgx_ec_key_128bit_t         vk_key;
    sgx_ec256_public_t          sp_pubkey;
    sgx_ec256_private_t         a;
    sgx_ps_sec_prop_desc_t      ps_sec_prop;
    sgx_ec_key_128bit_t         mk_key;
    sgx_ec_key_128bit_t         sk_key;
    sgx_ec_key_128bit_t         smk_key;
    sgx_quote_nonce_t           quote_nonce;
    sgx_target_info_t           qe_target; 
    ra_state                    state;
    sgx_spinlock_t              item_lock;
    uintptr_t                   derive_key_cb;
} ra_db_item_t;*/

#endif
