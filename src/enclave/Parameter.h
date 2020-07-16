#ifndef _ENCLAVE_RESOURCE_H_
#define _ENCLAVE_RESOURCE_H_

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

#define ENC_MAX_THREAD_NUM  15

#endif /* !_ENCLAVE_RESOURCE_H_ */
