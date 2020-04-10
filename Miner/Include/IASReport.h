#ifndef _CRUST_IASREPORTE_H_
#define _CRUST_IASREPORTE_H_

#define REPORT_DATA_SIZE	    64
#define ACCOUNT_SIZE	        48
#define SIGNER_ID_SIZE          SGX_ECP256_KEY_SIZE*2

#define IAS_TRYOUT              6
#define IAS_TIMEOUT             10
#define CLIENT_TIMEOUT          30

#define IAS_API_DEF_VERSION     3

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
