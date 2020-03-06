#ifndef _CRUST_IASREPORTE_H_
#define _CRUST_IASREPORTE_H_

#define REPORT_DATA_SIZE	    64
#define ACCOUNT_SIZE	        48
#define SIGNER_ID_SIZE          SGX_ECP256_KEY_SIZE*2

#define IAS_TRYOUT              6
#define IAS_TIMEOUT             10
#define CLIENT_TIMEOUT          30

#define IAS_API_DEF_VERSION     3

#define IAS_MK_ERROR(x) (0x00000000 | (x))

typedef enum _ias_status_t
{
    IAS_QUERY_FAILED = IAS_MK_ERROR(0),
    IAS_OK = IAS_MK_ERROR(200),
    IAS_VERIFY_SUCCESS = IAS_MK_ERROR(2000),
    IAS_VERIFY_FAILED = IAS_MK_ERROR(2001),
    IAS_BADREQUEST = IAS_MK_ERROR(400),
    IAS_UNAUTHORIZED = IAS_MK_ERROR(401),
    IAS_NOT_FOUND = IAS_MK_ERROR(404),
    IAS_SERVER_ERR = IAS_MK_ERROR(500),
    IAS_UNAVAILABLE = IAS_MK_ERROR(503),
    IAS_INTERNAL_ERROR = IAS_MK_ERROR(1000),
    IAS_BAD_CERTIFICATE = IAS_MK_ERROR(1001),
    IAS_BAD_SIGNATURE = IAS_MK_ERROR(1002),
    IAS_BAD_BODY = IAS_MK_ERROR(1003),
    IAS_REPORTDATA_NE = IAS_MK_ERROR(1004),
    IAS_GET_REPORT_FAILED = IAS_MK_ERROR(1005),
    IAS_BADMEASUREMENT = IAS_MK_ERROR(1006),
    IAS_GETPUBKEY_FAILED = IAS_MK_ERROR(1007),
    CRUST_SIGN_PUBKEY_FAILED = IAS_MK_ERROR(1008),
    CRUST_GET_ACCOUNT_ID_BYTE_FAILED = IAS_MK_ERROR(1009),
} ias_status_t;

typedef struct _entry_network_signature
{
    uint8_t pub_key[REPORT_DATA_SIZE];
    uint8_t validator_pub_key[REPORT_DATA_SIZE];
    sgx_ec256_signature_t signature;
} entry_network_signature;

typedef struct _ecc_key_pair
{
    sgx_ec256_public_t pub_key;
    sgx_ec256_private_t pri_key;
} ecc_key_pair;

#endif /* !_CRUST_IASREPORTE_H_ */
