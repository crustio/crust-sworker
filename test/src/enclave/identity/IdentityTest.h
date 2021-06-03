#ifndef _CRUST_IDENTITY_TEST_H_
#define _CRUST_IDENTITY_TEST_H_

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
#include <sgx_report.h>
#include "sgx_spinlock.h"
#include "sgx_thread.h"

#include "Enclave_t.h"
#include "IASReport.h"
#include "tSgxSSL_api.h"
#include "EUtils.h"
#include "Persistence.h"
#include "ReportTest.h"
#include "Parameter.h"

using namespace std;
crust_status_t id_gen_upgrade_data_test(size_t block_height);

#endif
