#ifndef _CRUST_API_HANDLER_TEST_H_
#define _CRUST_API_HANDLER_TEST_H_

#include <stdio.h>
#include <algorithm>
#include <mutex>
#include <set>
#include <exception>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <sgx_report.h>
#include <sgx_key_exchange.h>
#include <sgx_error.h>
#include "sgx_eid.h"
#include "sgx_tcrypto.h"

#include "Common.h"
#include "Config.h"
#include "FormatUtils.h"
#include "IASReport.h"
#include "SgxSupport.h"
#include "Resource.h"
#include "HttpClient.h"
#include "FileUtils.h"
#include "Log.h"
#include "sgx_tseal.h"
#include "Config.h"
#include "Common.h"
#include "DataBase.h"
#include "Srd.h"
#include "SrdTest.h"
#include "AsyncTest.h"
#include "EnclaveData.h"
#include "EnclaveDataTest.h"
#include "Chain.h"

json::JSON http_handler_test(UrlEndPoint urlendpoint, json::JSON req);

#endif /* !_CRUST_API_HANDLER_TEST_H_ */
