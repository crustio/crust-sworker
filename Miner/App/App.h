#ifndef _CRUST_APP_H_
#define _CRUST_APP_H_

#include <stdio.h>
#include <string>
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "OCalls/OCalls.h"
#include "Ipfs/Ipfs.h"

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

/* Normal functions */
int initialize_enclave(void);

#endif /* !_CRUST_APP_H_ */
