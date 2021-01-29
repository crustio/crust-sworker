#ifndef _CRUST_WORK_REPORT_H_
#define _CRUST_WORK_REPORT_H_

#include <string>
#include <stdlib.h>
#include <time.h>

#include <sgx_eid.h>

#include "ECalls.h"
#include "Config.h"
#include "Log.h"
#include "Chain.h"
#include "CrustStatus.h"
#include "FormatUtils.h"
#include "EnclaveData.h"

void work_report_loop(void);

#endif /* !_CRUST_WORK_REPORT_H_ */
