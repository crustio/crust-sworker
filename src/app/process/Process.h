#ifndef _CRUST_PROCESS_H_
#define _CRUST_PROCESS_H_

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>
#include <unistd.h>
#include <algorithm>
#include <mutex>
#include <map>
#include <fstream>

#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <sgx_uae_service.h>
#include <sgx_error.h>
#include <sgx_eid.h>
#include <sgx_urts.h>
#include <sgx_capable.h>

#include "Enclave_u.h"
#include "SgxSupport.h"
#include "Config.h"
#include "Chain.h"
#include "FormatUtils.h"
#include "Common.h"
#include "Resource.h"
#include "FileUtils.h"
#include "Log.h"
#include "EntryNetwork.h"
#include "WorkReportLoop.h"

int process_run();

#endif /* !_CRUST_PROCESS_H_ */
