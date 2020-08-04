#ifndef _ENCLAVE_RESOURCE_H_
#define _ENCLAVE_RESOURCE_H_

#define TEE_VERSION "0.5.0"

#define LEAF_SEPARATOR  "+leaf+"

// For enclave metadata
#define ID_METADATA "metadata"
#define ID_FILE "files"
#define ID_WORKLOAD "workload"
#define ID_KEY_PAIR "id_key_pair"
#define ID_REPORT_SLOG "report_slot"
#define ID_CHAIN_ACCOUNT_ID "chain_account_id"

// For meaningful file
#define FILE_HASH "hash"
#define FILE_SIZE "size"
#define FILE_OLD_SIZE "old_size"
#define FILE_OLD_HASH "old_hash"
#define FILE_BLOCK_NUM "block_num"
#define FILE_STATUS "status"
#define FILE_STATUS_LOST "lost"
#define FILE_STATUS_VALID "valid"
#define FILE_STATUS_UNCONFIRMED "unconfirmed"

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
#define WORKREPORT_BLOCK_HEIGHT "block_height"
#define WORKREPORT_BLOCK_HASH "block_hash"
#define WORKREPORT_RESERVED "reserved"
#define WORKREPORT_FILES "files"
#define WORKREPORT_SIG "sig"

// For order report
#define ORDERREPORT_FILES "files"
#define ORDERREPORT_PUB_KEY "pub_key"
#define ORDERREPORT_RANDOM "random"
#define ORDERREPORT_SIG "sig"

// For workload
#define WL_SRD "srd"
#define WL_SRD_ROOT_HASH "root_hash"
#define WL_SRD_SPACE "space"
#define WL_SRD_REMAINING_TASK "remaining_task"
#define WL_FILES "files"
#define WL_FILE_SEALED_SIZE "sealed_size"
#define WL_FILE_STATUS "status"
#define WL_FILE_OLD_HASH "old_hash"
#define WL_FILE_OLD_SIZE "old_size"

// Basic parameters
#define HASH_LENGTH 32
#define ENC_MAX_THREAD_NUM  15
#define ENCLAVE_MALLOC_TRYOUT 3

#endif /* !_ENCLAVE_RESOURCE_H_ */
