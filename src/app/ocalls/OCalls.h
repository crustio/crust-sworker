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
#include "FileUtils.h"
#include "FormatUtils.h"
#include "Common.h"
#include "Log.h"
#include "CrustStatus.h"
#include "WebsocketClient.h"

#if defined(__cplusplus)
extern "C"
{
#endif

    void ocall_print_string(const char *str);
    void ocall_log_info(const char *str);
    void ocall_log_warn(const char *str);
    void ocall_log_err(const char *str);
    void ocall_log_debug(const char *str);

    crust_status_t ocall_create_dir(const char *path);
    crust_status_t ocall_rename_dir(const char *old_path, const char *new_path);
    crust_status_t ocall_save_file(const char *file_path, const unsigned char *data, size_t len);
    size_t ocall_get_folders_number_under_path(const char *path);
    crust_status_t ocall_delete_folder_or_file(const char *path);
    void ocall_store_sealed_merkletree(const char *org_root_hash, const char *tree_data, size_t tree_len);
    void ocall_get_sub_folders_and_files(const char *path, char ***files, size_t *files_num);
    crust_status_t ocall_replace_file(const char *old_path, const char *new_path, const uint8_t *data, size_t len);
    crust_status_t ocall_get_file(const char *file_path, unsigned char **p_file, size_t *len);
    crust_status_t ocall_get_storage_file(const char *file_path, unsigned char **p_file, size_t *len);
    void ocall_usleep(int u);
    crust_status_t ocall_get_file_block_by_path(char *root_hash, char *cur_hash, uint32_t hash_len, uint32_t *path, uint32_t path_count);

    crust_status_t ocall_persist_add(const char *key, const uint8_t *value, size_t value_len);
    crust_status_t ocall_persist_del(const char *key);
    crust_status_t ocall_persist_set(const char *key, const uint8_t *value, size_t value_len);
    crust_status_t ocall_persist_get(const char *key, uint8_t **value, size_t *value_len);

    crust_status_t ocall_validate_init();
    crust_status_t ocall_validate_get_file(const char *root_hash, const char *leaf_hash, uint8_t **p_sealed_data, size_t *sealed_data_size);
    void ocall_validate_close();

#if defined(__cplusplus)
}
#endif

#endif /* !_OCALLS_APP_H_ */
