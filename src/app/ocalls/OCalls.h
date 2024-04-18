#ifndef _CRUST_OCALLS_H_
#define _CRUST_OCALLS_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <exception>

#include "CrustStatus.h"
#include "FileUtils.h"
#include "FormatUtils.h"
#include "Config.h"
#include "Common.h"
#include "Log.h"
#include "EnclaveData.h"
#include "WebsocketClient.h"
#include "Srd.h"
#include "DataBase.h"
#include "EntryNetwork.h"
#include "Chain.h"
#include "Validator.h"
#include "SafeLock.h"

#if defined(__cplusplus)
extern "C"
{
#endif

    // For log
    void ocall_print_info(const char *str);
    void ocall_print_debug(const char *str);
    void ocall_log_info(const char *str);
    void ocall_log_warn(const char *str);
    void ocall_log_err(const char *str);
    void ocall_log_debug(const char *str);

    // For file
    crust_status_t ocall_chain_get_block_info(uint8_t *data, size_t data_size, size_t *real_size);
    void ocall_store_file_info(const char* cid, const char *data, const char *type);
    crust_status_t ocall_store_file_info_all(const uint8_t *data, size_t data_size);
    
    void ocall_usleep(int u);
    crust_status_t ocall_free_outer_buffer(uint8_t **value);

    // For srd
    crust_status_t ocall_srd_change(long change);

    // For enclave data to app
    void ocall_store_enclave_id_info(const char *info);
    crust_status_t ocall_store_workreport(const uint8_t *data, size_t data_size);
    crust_status_t ocall_store_upgrade_data(const uint8_t *data, size_t data_size);

    // For upgrade
    crust_status_t ocall_get_block_hash(size_t block_height, char *block_hash, size_t hash_size);
    crust_status_t ocall_upload_workreport();
    crust_status_t ocall_upload_epid_identity(const char *id);
    crust_status_t ocall_upload_ecdsa_quote(const char *id);
    crust_status_t ocall_upload_ecdsa_identity(const char *id);
    crust_status_t ocall_entry_network();

    void ocall_recall_validate_file();
    void ocall_recall_validate_srd();

    void ocall_change_file_type(const char *cid, const char *old_type, const char *new_type);
    void ocall_delete_file_info(const char *cid, const char *type);

    crust_status_t ocall_safe_store2(ocall_store_type_t t, const uint8_t *data, size_t total_size, size_t partial_size, size_t offset, uint32_t buffer_key);

#if defined(__cplusplus)
}
#endif

#endif /* !_OCALLS_APP_H_ */
