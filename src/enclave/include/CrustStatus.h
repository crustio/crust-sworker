#ifndef _CRUST_CRUST_STATUS_H_
#define _CRUST_CRUST_STATUS_H_

#define CRUST_SEPARATOR "$crust_separator$"

#define CRUST_MK_ERROR(x) (0x00000000 | (x))

typedef enum _crust_status_t
{
    // Successed
    CRUST_SUCCESS = CRUST_MK_ERROR(0),
       
    // Work report
    CRUST_BLOCK_HEIGHT_EXPIRED = CRUST_MK_ERROR(0x2000),
    CRUST_FIRST_WORK_REPORT_AFTER_REPORT = CRUST_MK_ERROR(0x2001),
    CRUST_WORK_REPORT_NOT_VALIDATED = CRUST_MK_ERROR(0x2002),
    CRUST_SERVICE_UNAVAILABLE = CRUST_MK_ERROR(0x2003),
    
    // Failed
    CRUST_MALLOC_FAILED = CRUST_MK_ERROR(0x4000),
    CRUST_SEAL_DATA_FAILED = CRUST_MK_ERROR(0x4001),
    CRUST_UNSEAL_DATA_FAILED = CRUST_MK_ERROR(0x4002),
    CRUST_STORE_DATA_TO_FILE_FAILED = CRUST_MK_ERROR(0x4003),
    CRUST_GET_DATA_FROM_FILE_FAILED = CRUST_MK_ERROR(0x4004),
    CRUST_BAD_SEAL_DATA = CRUST_MK_ERROR(0x4005),
    CRUST_SGX_FAILED = CRUST_MK_ERROR(0x4006),
    CRUST_DOUBLE_SET_VALUE = CRUST_MK_ERROR(0x4007),
    CRUST_NOT_EQUAL = CRUST_MK_ERROR(0x4008),
    CRUST_SGX_SIGN_FAILED = CRUST_MK_ERROR(0x4009),
    CRUST_SGX_VERIFY_SIG_FAILED = CRUST_MK_ERROR(0x4010),
    CRUST_UNEXPECTED_ERROR = CRUST_MK_ERROR(0x4011),
    CRUST_INVALID_MERKLETREE = CRUST_MK_ERROR(0x4012),
    CRUST_NOTFOUND_MERKLETREE = CRUST_MK_ERROR(0x4013),
    CRUST_INVALID_SEALED_DATA = CRUST_MK_ERROR(0x4014),
    CRUST_VERIFY_MEANINGFUL_FAILED = CRUST_MK_ERROR(0x4015),
    CRUST_GET_FILE_BLOCK_FAILED = CRUST_MK_ERROR(0x4016),
    CRUST_WRONG_FILE_BLOCK = CRUST_MK_ERROR(0x4017),
    CRUST_SEAL_NOTCOMPLETE = CRUST_MK_ERROR(0x4018),
    CRUST_DESER_MERKLE_TREE_FAILED = CRUST_MK_ERROR(0x4019),
    CRUST_GET_MERKLETREE_FAILED = CRUST_MK_ERROR(0x4020),
    CRUST_MERKLETREE_DUPLICATED = CRUST_MK_ERROR(0x4021),
    CRUST_MALWARE_DATA_BLOCK = CRUST_MK_ERROR(0x4022),
    CRUST_DUPLICATED_SEAL = CRUST_MK_ERROR(0x4023),
    CRUST_OPEN_FILE_FAILED = CRUST_MK_ERROR(0x4024),
    CRUST_WRITE_FILE_FAILED = CRUST_MK_ERROR(0x4025),
    CRUST_DELETE_FILE_FAILED = CRUST_MK_ERROR(0x4026),
    CRUST_RENAME_FILE_FAILED = CRUST_MK_ERROR(0x4027),
    CRUST_RENAME_FILE_NOTFOUND = CRUST_MK_ERROR(0x4028),
    CRUST_MKDIR_FAILED = CRUST_MK_ERROR(0x4029),
    CRUST_ACCESS_FILE_FAILED = CRUST_MK_ERROR(0x4030),
    CRUST_INVALID_META_DATA = CRUST_MK_ERROR(0x4031),
    CRUST_METADATA_NOTFOUND = CRUST_MK_ERROR(0x4032),
    CRUST_START_WEB_SERVICE_FAILED = CRUST_MK_ERROR(0x4033),
    CRUST_ENTRY_NETWORK_FAILED = CRUST_MK_ERROR(0x4034),
    CRUST_SEND_IDENTITY_FAILED = CRUST_MK_ERROR(0x4035),
    CRUST_INIT_QUOTE_FAILED = CRUST_MK_ERROR(0x4036),
    CRUST_SRD_NUMBER_EXCEED = CRUST_MK_ERROR(0x4037),
    CRUST_FILE_NUMBER_EXCEED = CRUST_MK_ERROR(0x4038),
    CRUST_DEVICE_ERROR = CRUST_MK_ERROR(0x4039),

    // Persistence related
    CRUST_PERSIST_ADD_FAILED = CRUST_MK_ERROR(0x6001),
    CRUST_PERSIST_DEL_FAILED = CRUST_MK_ERROR(0x6002),
    CRUST_PERSIST_SET_FAILED = CRUST_MK_ERROR(0x6003),
    CRUST_PERSIST_GET_FAILED = CRUST_MK_ERROR(0x6004),

    // IAS report related
    CRUST_IAS_QUERY_FAILED = CRUST_MK_ERROR(0x7001),
    CRUST_IAS_OK = CRUST_MK_ERROR(0x7002),
    CRUST_IAS_VERIFY_FAILED = CRUST_MK_ERROR(0x7003),
    CRUST_IAS_BADREQUEST = CRUST_MK_ERROR(0x7004),
    CRUST_IAS_UNAUTHORIZED = CRUST_MK_ERROR(0x7005),
    CRUST_IAS_NOT_FOUND = CRUST_MK_ERROR(0x7006),
    CRUST_IAS_UNEXPECTED_ERROR = CRUST_MK_ERROR(0x7007),
    CRUST_IAS_SERVER_ERR = CRUST_MK_ERROR(0x7008),
    CRUST_IAS_UNAVAILABLE = CRUST_MK_ERROR(0x7009),
    CRUST_IAS_INTERNAL_ERROR = CRUST_MK_ERROR(0x7010),
    CRUST_IAS_BAD_CERTIFICATE = CRUST_MK_ERROR(0x7011),
    CRUST_IAS_BAD_SIGNATURE = CRUST_MK_ERROR(0x7012),
    CRUST_IAS_BAD_BODY = CRUST_MK_ERROR(0x7013),
    CRUST_IAS_REPORTDATA_NE = CRUST_MK_ERROR(0x7014),
    CRUST_IAS_GET_REPORT_FAILED = CRUST_MK_ERROR(0x7015),
    CRUST_IAS_BADMEASUREMENT = CRUST_MK_ERROR(0x7016),
    CRUST_IAS_GETPUBKEY_FAILED = CRUST_MK_ERROR(0x7017),
    CRUST_SIGN_PUBKEY_FAILED = CRUST_MK_ERROR(0x7018),
    CRUST_GET_ACCOUNT_ID_BYTE_FAILED = CRUST_MK_ERROR(0x7019),
    CRUST_SWORKER_UPGRADE_NEEDED = CRUST_MK_ERROR(0x7020),
    
    // Storage related
    CRUST_STORAGE_SER_MERKLETREE_FAILED = CRUST_MK_ERROR(0x8001),
    CRUST_STORAGE_UPDATE_FILE_FAILED = CRUST_MK_ERROR(0x8002),
    CRUST_STORAGE_UNSEAL_FILE_FAILED = CRUST_MK_ERROR(0x8003),
    CRUST_STORAGE_UNEXPECTED_FILE_BLOCK = CRUST_MK_ERROR(0x8004),
    CRUST_STORAGE_NEW_FILE_NOTFOUND = CRUST_MK_ERROR(0x8005),
    CRUST_STORAGE_NEW_FILE_SIZE_ERROR = CRUST_MK_ERROR(0x8006),
    CRUST_STORAGE_EMPTY_BLOCK = CRUST_MK_ERROR(0x8007),
    CRUST_STORAGE_IPFS_BLOCK_GET_ERROR = CRUST_MK_ERROR(0x8008),
    CRUST_STORAGE_IPFS_CAT_ERROR = CRUST_MK_ERROR(0x8009),
    CRUST_STORAGE_IPFS_ADD_ERROR = CRUST_MK_ERROR(0x8010),
    CRUST_STORAGE_IPFS_DEL_ERROR = CRUST_MK_ERROR(0x8011),
    CRUST_STORAGE_FILE_DUP = CRUST_MK_ERROR(0x8012),
    CRUST_STORAGE_FILE_SEALING = CRUST_MK_ERROR(0x8013),
    CRUST_STORAGE_FILE_DELETING = CRUST_MK_ERROR(0x8014),
    CRUST_STORAGE_FILE_BLOCK_NOTFOUND = CRUST_MK_ERROR(0x8015),

    // Validation related
    CRUST_VALIDATE_GET_REQUEST_FAILED = CRUST_MK_ERROR(0x9001),

    // Upgrade related
    CRUST_UPGRADE_RESTORE_SRD_FAILED = CRUST_MK_ERROR(0x10001),
    CRUST_UPGRADE_RESTORE_FILE_FAILED = CRUST_MK_ERROR(0x10002),
    CRUST_UPGRADE_SEND_WORKREPORT_FAILED = CRUST_MK_ERROR(0x10003),
    CRUST_UPGRADE_INVALID_WORKREPORT = CRUST_MK_ERROR(0x10004),
    CRUST_UPGRADE_GET_BLOCK_HASH_FAILED = CRUST_MK_ERROR(0x10005),
    CRUST_UPGRADE_GEN_WORKREPORT_FAILED = CRUST_MK_ERROR(0x10006),
    CRUST_UPGRADE_WAIT_FOR_NEXT_ERA = CRUST_MK_ERROR(0x10007),
    CRUST_UPGRADE_BAD_SRD = CRUST_MK_ERROR(0x10008),
    CRUST_UPGRADE_BAD_FILE = CRUST_MK_ERROR(0x10009),
    CRUST_UPGRADE_IS_UPGRADING = CRUST_MK_ERROR(0x10010),
    CRUST_UPGRADE_NEED_LEFT_DATA = CRUST_MK_ERROR(0x10011),
    CRUST_UPGRADE_BLOCK_EXPIRE = CRUST_MK_ERROR(0x10012),
    CRUST_UPGRADE_NO_VALIDATE = CRUST_MK_ERROR(0x10013),
    CRUST_UPGRADE_RESTART = CRUST_MK_ERROR(0x10014),
    CRUST_UPGRADE_NO_FILE = CRUST_MK_ERROR(0x10015),

    // For http
    CRUST_INVALID_HTTP_INPUT = CRUST_MK_ERROR(0x11001),
} crust_status_t;

#endif /* !_CRUST_CRUST_STATUS_H_ */
