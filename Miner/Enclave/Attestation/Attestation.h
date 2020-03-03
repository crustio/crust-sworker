#ifndef _CRUST_LOCAL_ATTESTATION_H_
#define _CRUST_LOCAL_ATTESTATION_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"

#include "IPCReport.h"
#include "IASReport.h"
#include "EUtils.h"
#include "Workload.h"

#define SAFE_FREE(ptr)     {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#endif /* _CRUST_LOCAL_ATTESTATION_H_ */
