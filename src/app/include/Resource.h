#define VERSION "0.5.1"

#define CRUST_INST_DIR      "/opt/crust/crust-sworker/" VERSION
#define ENCLAVE_FILE_PATH   CRUST_INST_DIR "/etc/enclave.signed.so"

#define HASH_LENGTH 32
#define SEAL_BLOCK_MAX_SIZE 2097152 /* 2*1024*1024 */
#define WEB_TIMEOUT 1000
#define ENCLAVE_MALLOC_TRYOUT 3

// For db data
#define DB_SRD_INFO "srd_info"

// For buffer pool
#define BUFFER_AVAILABLE "buffer_available"
