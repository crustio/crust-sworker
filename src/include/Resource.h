#define VERSION "0.5.0"

#define CRUST_INST_DIR      "/opt/crust/crust-tee/" VERSION
#define ENCLAVE_FILE_PATH   CRUST_INST_DIR "/etc/enclave.signed.so"
#define CONFIG_FILE_PATH    CRUST_INST_DIR "/etc/Config.json"

#define HASH_LENGTH 32
#define SEAL_BLOCK_MAX_SIZE 2097152 /* 2*1024*1024 */
#define WEB_TIMEOUT 60
#define ENCLAVE_MALLOC_TRYOUT 3
