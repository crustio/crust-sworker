#ifndef _CRUST_RESOURCE_H_
#define _CRUST_RESOURCE_H_

#include <stdint.h>
#include "../enclave/include/Parameter.h"

#define VERSION "0.7.0"

#define CRUST_INST_DIR      "/opt/crust/crust-sworker/" VERSION
#define ENCLAVE_FILE_PATH   CRUST_INST_DIR "/etc/enclave.signed.so"

// For work report
// REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT < REPORT_SLOT
// REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT > REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT
#define REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT 200
// REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT > 0
#define REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT 10

#define HTTP_BODY_LIMIT 104857600 /* 100*1024*1024 */
#define WEB_TIMEOUT 7200

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

const uint32_t UPGRADE_START_TRYOUT = BLOCK_INTERVAL * REPORT_SLOT * 5;
const uint32_t UPGRADE_META_TRYOUT = BLOCK_INTERVAL * REPORT_SLOT;
const uint32_t UPGRADE_COMPLETE_TRYOUT = BLOCK_INTERVAL * 10;

#define ID_METADATA_OLD "metadata_old"

// For workload
#define WL_DISK_AVAILABLE "disk_available"
#define WL_DISK_AVAILABLE_FOR_SRD "disk_available_for_srd"
#define WL_DISK_RESERVED "disk_reserved"
#define WL_DISK_VOLUME "disk_volume"

// For print
#define PRINT_GAP 20
#define RED "\033[0;31m"
#define HRED "\033[1;31m"
#define NC "\033[0m"
const char* ATTENTION_LOGO = "    ___   __  __             __  _                __   __   __\n"
                             "   /   | / /_/ /____  ____  / /_(_)___  ____     / /  / /  / /\n"
                             "  / /| |/ __/ __/ _ %/ __ %/ __/ / __ %/ __ %   / /  / /  / / \n"
                             " / ___ / /_/ /_/  __/ / / / /_/ / /_/ / / / /  /_/  /_/  /_/  \n"
                             "/_/  |_%__/%__/%___/_/ /_/%__/_/%____/_/ /_/  (_)  (_)  (_)   \n";

// Webserver return format
#define HTTP_STATUS_CODE "status_code"
#define HTTP_MESSAGE "message"

#endif /* !_CRUST_RESOURCE_H_ */
