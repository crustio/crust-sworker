#ifndef _ENCLAVE_RESOURCE_H_
#define _ENCLAVE_RESOURCE_H_

#define TEE_VERSION "0.5.1"

#define LEAF_SEPARATOR  "+leaf+"

// For persistence
#define OCALL_STORE_THRESHOLD 4194304 /* 4*1024*1024 */

// For enclave metadata
#define ID_METADATA "metadata"
#define ID_FILE "files"
#define ID_WORKLOAD "workload"
#define ID_KEY_PAIR "id_key_pair"
#define ID_REPORT_SLOT "report_slot"
#define ID_CHAIN_ACCOUNT_ID "chain_account_id"

// For meaningful file
#define FILE_HASH "hash"
#define FILE_SIZE "size"
#define FILE_OLD_SIZE "old_size"
#define FILE_OLD_HASH "old_hash"
#define FILE_BLOCK_NUM "block_num"
#define FILE_STATUS "status"
#define FILE_STATUS_UNCONFIRMED '0'
#define FILE_STATUS_VALID '1'
#define FILE_STATUS_LOST '2'
#define FILE_STATUS_DELETED '3'
// Current status
#define CURRENT_STATUS 0
// Wait to sync status
#define WAITING_STATUS 1
// Old status
#define ORIGIN_STATUS 2

// For DB data
#define DB_SRD_INFO "srd_info"

// For Merkle tree
#define MT_LINKS_NUM "links_num"
#define MT_LINKS "links"
#define MT_HASH "hash"
#define MT_SIZE "size"

// For IAS report
#define IAS_CERT "ias_cert"
#define IAS_SIG "ias_sig"
#define IAS_ISV_BODY "isv_body"
#define IAS_CHAIN_ACCOUNT_ID "account_id"
#define IAS_REPORT_SIG "sig"
#define IAS_ISV_BODY_TAG "isvEnclaveQuoteBody"

// For work report
#define WORKREPORT_PUB_KEY "pub_key"
#define WORKREPORT_PRE_PUB_KEY "pre_pub_key"
#define WORKREPORT_BLOCK_HEIGHT "block_height"
#define WORKREPORT_BLOCK_HASH "block_hash"
#define WORKREPORT_RESERVED "reserved"
#define WORKREPORT_FILES_SIZE "files_size"
#define WORKREPORT_RESERVED_ROOT "reserved_root"
#define WORKREPORT_FILES_ROOT "files_root"
#define WORKREPORT_FILES_ADDED "added_files"
#define WORKREPORT_FILES_DELETED "deleted_files"
#define WORKREPORT_SIG "sig"
#define WORKREPORT_FILE_LIMIT 1000

// For order report
#define ORDERREPORT_FILES "files"
#define ORDERREPORT_PUB_KEY "pub_key"
#define ORDERREPORT_RANDOM "random"
#define ORDERREPORT_SIG "sig"

// For workload
#define WL_SRD "srd"
#define WL_SRD_DETAIL "detail"
#define WL_SRD_ROOT_HASH "root_hash"
#define WL_SRD_SPACE "space"
#define WL_SRD_REMAINING_TASK "remaining_task"
#define WL_FILES "files"
#define WL_FILE_SEALED_SIZE "sealed_size"
#define WL_FILE_STATUS "status"
#define WL_FILE_OLD_HASH "old_hash"
#define WL_FILE_OLD_SIZE "old_size"

// For ocalls
#define PERSIST_SUM "persist_sum"
#define PERSIST_SIZE "persist_size"

// Basic parameters
#define HASH_LENGTH 32
#define ENC_MAX_THREAD_NUM  15
#define ENCLAVE_MALLOC_TRYOUT 3

// For buffer pool
#define BUFFER_AVAILABLE "buffer_available"

#endif /* !_ENCLAVE_RESOURCE_H_ */
