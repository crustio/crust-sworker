#ifndef _CRUST_WORK_REPORT_H_
#define _CRUST_WORK_REPORT_H_

#include <string>
#include <stdlib.h>
#include <time.h>

#include <sgx_eid.h>
#include "Enclave_u.h"

#include "Config.h"
#include "Log.h"
#include "Chain.h"
#include "CrustStatus.h"
#include "FormatUtils.h"

#define REPORT_BLOCK_HEIGHT_BASE 300
#define BLOCK_INTERVAL 6

// REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT < REPORT_BLOCK_HEIGHT_BASE
// REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT > REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT
#define REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT 200

// REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT > 0
#define REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT 10

void *work_report_loop(void *);

#endif /* !_CRUST_WORK_REPORT_H_ */
