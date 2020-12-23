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
#include "Chain.h"
#include "EntryNetwork.h"
#include "Chain.h"

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
    void ocall_store_unsealed_data(const char *unsealed_root, uint8_t *p_unsealed_data, size_t unsealed_data_len);
    crust_status_t ocall_chain_get_block_info(char *data, size_t data_size);
    void ocall_store_file_info(const char* cid, const char *data);
    
    void ocall_usleep(int u);
    crust_status_t ocall_free_outer_buffer(uint8_t **value);

    // For srd
    void ocall_srd_change(long change);

    // For enclave data to app
    void ocall_store_enclave_id_info(const char *info);
    void ocall_store_workload(const char *data, size_t data_size, bool cover = true);
    void ocall_store_upgrade_data(const char *data, size_t data_size, bool cover = true);

    // For upgrade
    crust_status_t ocall_get_block_hash(size_t block_height, char *block_hash, size_t hash_size);
    crust_status_t ocall_upload_workreport(const char *work_report);
    crust_status_t ocall_upload_identity(const char *id);
    crust_status_t ocall_entry_network();

#if defined(__cplusplus)
}
#endif

#endif /* !_OCALLS_APP_H_ */
