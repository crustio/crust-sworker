#ifndef _CRUST_RESOURCE_H_
#define _CRUST_RESOURCE_H_

#include <stdint.h>
#include "../enclave/include/Parameter.h"

#define VERSION "0.7.0"

#define CRUST_INST_DIR      "/opt/crust/crust-sworker/" VERSION
#define ENCLAVE_FILE_PATH   CRUST_INST_DIR "/etc/enclave.signed.so"

// For work report
#define REPORT_BLOCK_HEIGHT_BASE 300
#define BLOCK_INTERVAL 6
// REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT < REPORT_BLOCK_HEIGHT_BASE
// REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT > REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT
#define REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT 200
// REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT > 0
#define REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT 10

#define SEAL_BLOCK_MAX_SIZE 2097152 /* 2*1024*1024 */
#define WEB_TIMEOUT 1000
#define ENCLAVE_MALLOC_TRYOUT 3

#define OCALL_STORE_THRESHOLD 4194304 /* 4*1024*1024 */

// For upgrade
typedef enum _upgrade_status_t
{
    UPGRADE_STATUS_NONE,            // No upgrade
    UPGRADE_STATUS_STOP_WORKREPORT, // Block work-report
    UPGRADE_STATUS_PROCESS,         // Processing running tasks
    UPGRADE_STATUS_END,             // Finish running tasks and generate uprade data successfully
    UPGRADE_STATUS_COMPLETE,        // Finish generating upgrade data
    UPGRADE_STATUS_EXIT,            // Will exit process
} upgrade_status_t;

const uint32_t UPGRADE_START_TRYOUT = BLOCK_INTERVAL * REPORT_BLOCK_HEIGHT_BASE * 5;
const uint32_t UPGRADE_META_TRYOUT = BLOCK_INTERVAL * REPORT_BLOCK_HEIGHT_BASE / 5;
const uint32_t UPGRADE_COMPLETE_TRYOUT = BLOCK_INTERVAL * 10;

#define ID_METADATA_OLD "metadata_old"
#define ID_METADATA "metadata"

#endif /* !_CRUST_RESOURCE_H_ */
