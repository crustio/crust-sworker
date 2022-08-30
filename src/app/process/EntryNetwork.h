#ifndef _CRUST_ENTRY_NETWORK_H_
#define _CRUST_ENTRY_NETWORK_H_

#include <string>
#include <stdlib.h>

#include "Resource.h"
#include "Chain.h"
#include "Common.h"
#include "Config.h"
#include "Log.h"
#include "SgxSupport.h"
#include "FormatUtils.h"
#include "CrustStatus.h"
#include "EnclaveData.h"
#include "HttpClient.h"

// For EPID
#include <sgx_eid.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
// For ECDSA
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "sgx_utils.h"
#include "sgx_urts.h"

#define OPT_ISSET(x, y) x &y
#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#define OPT_PSE 0x01
#define OPT_NONCE 0x02
#define OPT_LINK 0x04
#define OPT_PUBKEY 0x08

crust_status_t entry_network();

#endif /* !_CRUST_ENTRY_NETWORK_H_ */
