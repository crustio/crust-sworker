#ifndef _CRUST_WORK_REPORT_H_
#define _CRUST_WORK_REPORT_H_

#include <string>
#include <stdlib.h>

#include <sgx_eid.h>
#include "Enclave_u.h"

#include "Config.h"
#include "Log.h"
#include "Chain.h"
#include "CrustStatus.h"

#define REPORT_BLOCK_HEIGHT_BASE 300

void *work_report_loop(void *);

#endif /* !_CRUST_WORK_REPORT_H_ */
