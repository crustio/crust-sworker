#ifndef _CRUST_RESOURCE_H_
#define _CRUST_RESOURCE_H_

#define VERSION "0.6.0"

#define CRUST_INST_DIR      "/opt/crust/crust-sworker/" VERSION
#define ENCLAVE_FILE_PATH   CRUST_INST_DIR "/etc/enclave.signed.so"

#define HASH_LENGTH 32
#define SEAL_BLOCK_MAX_SIZE 2097152 /* 2*1024*1024 */
#define WEB_TIMEOUT 1000
#define ENCLAVE_MALLOC_TRYOUT 3
#define UPGRADE_GEN_METADATA_TRYOUT 100
#define UPGRADE_START_TRYOUT 43200 /* 2x6x3600 = 12 hours*/
#define UPGRADE_META_TRYOUT 360
#define UPGRADE_COMPLETE_TRYOUT 100
#define UPGRADE_TIMEOUT 10800 /* 6x1800 half era */

#define OCALL_STORE_THRESHOLD 4194304 /* 4*1024*1024 */

// For db data
#define DB_SRD_INFO "srd_info"

// For upgrade
typedef enum _upgrade_status_t
{
    UPGRADE_STATUS_NONE,    // No upgrade
    UPGRADE_STATUS_PROCESS, // Processing running tasks
    UPGRADE_STATUS_END,     // Finish running tasks and generate uprade data successfully
    UPGRADE_STATUS_COMPLETE,// Finish generating upgrade data
    UPGRADE_STATUS_EXIT,    // Will exit process
} upgrade_status_t;

#define ID_METADATA_OLD "metadata_old"
#define ID_METADATA "metadata"

#endif /* !_CRUST_RESOURCE_H_ */
