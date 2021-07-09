#ifndef _CRUST_RESOURCE_H_
#define _CRUST_RESOURCE_H_

#include <stdint.h>
#include "Parameter.h"

#define VERSION "0.10.0"

#define CRUST_INST_DIR      "/opt/crust/crust-sworker/" VERSION
#define ENCLAVE_FILE_PATH   CRUST_INST_DIR "/etc/enclave.signed.so"
#define SGX_WL_FILE_PATH    CRUST_INST_DIR "/etc/sgx_white_list_cert.bin"

#define HTTP_BODY_LIMIT 524288000 /* 500*1024*1024 */
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
#define WL_SYS_DISK_AVAILABLE "sys_disk_available"
#define WL_DISK_PATH "disk_path"
#define WL_DISK_USE "disk_use"
#define WL_DISK_UUID "disk_uuid"

// For srd
#define DISK_SWORKER_DIR "/sworker"
#define DISK_SRD_DIR    DISK_SWORKER_DIR "/srd"
#define DISK_FILE_DIR    DISK_SWORKER_DIR "/files"
#define DISK_UUID_FILE  DISK_SWORKER_DIR "/uuid"
#define SRD_THREAD_NUM 8

// For print
#define PRINT_GAP 20
#define RED "\033[0;31m"
#define HRED "\033[1;31m"
#define GREEN "\033[0;32m"
#define HGREEN "\033[1;32m"
#define NC "\033[0m"
const char* ATTENTION_LOGO = 
"    ___   __  __             __  _                __   __   __\n"
"   /   | / /_/ /____  ____  / /_(_)___  ____     / /  / /  / /\n"
"  / /| |/ __/ __/ _ %/ __ %/ __/ / __ %/ __ %   / /  / /  / / \n"
" / ___ / /_/ /_/  __/ / / / /_/ / /_/ / / / /  /_/  /_/  /_/  \n"
"/_/  |_%__/%__/%___/_/ /_/%__/_/%____/_/ /_/  (_)  (_)  (_)   \n";

const char* UPGRADE_SUCCESS_LOGO =
"   __  ______  __________  ___    ____  ______   _____ __  ______________________________ ________  ____    ____  __    __\n"
"  / / / / __ %/ ____/ __ %/   |  / __ %/ ____/  / ___// / / / ____/ ____/ ____/ ___/ ___// ____/ / / / /   / /% %/ /   / /\n"
" / / / / /_/ / / __/ /_/ / /| | / / / / __/     %__ %/ / / / /   / /   / __/  %__ %%__ %/ /_  / / / / /   / /  %  /   / / \n"
"/ /_/ / ____/ /_/ / _, _/ ___ |/ /_/ / /___    ___/ / /_/ / /___/ /___/ /___ ___/ /__/ / __/ / /_/ / /___/ /___/ /   /_/  \n"
"%____/_/    %____/_/ |_/_/  |_/_____/_____/   /____/%____/%____/%____/_____//____/____/_/    %____/_____/_____/_/   (_)   \n";

const char* UPGRADE_FAILED_LOGO =
"   __  ______  __________  ___    ____  ______   _________    ______    __________     __   __   __\n"
"  / / / / __ %/ ____/ __ %/   |  / __ %/ ____/  / ____/   |  /  _/ /   / ____/ __ %   / /  / /  / /\n"
" / / / / /_/ / / __/ /_/ / /| | / / / / __/    / /_  / /| |  / // /   / __/ / / / /  / /  / /  / / \n"
"/ /_/ / ____/ /_/ / _, _/ ___ |/ /_/ / /___   / __/ / ___ |_/ // /___/ /___/ /_/ /  /_/  /_/  /_/  \n"
"%____/_/    %____/_/ |_/_/  |_/_____/_____/  /_/   /_/  |_/___/_____/_____/_____/  (_)  (_)  (_)   \n";

// Webserver return format
#define HTTP_STATUS_CODE "status_code"
#define HTTP_MESSAGE "message"
#define HTTP_IPFS_INDEX_PATH "path"

typedef enum _save_file_type_t
{
    SF_NONE,
    SF_CREATE_DIR,
} save_file_type_t;

#endif /* !_CRUST_RESOURCE_H_ */
