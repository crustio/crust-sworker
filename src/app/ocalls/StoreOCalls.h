#ifndef _CRUST_STORE_OCALLS_H_
#define _CRUST_STORE_OCALLS_H_

#include "CrustStatus.h"
#include "Log.h"
#include "FileUtils.h"
#include "FormatUtils.h"

#if defined(__cplusplus)
extern "C"
{
#endif
crust_status_t ocall_create_dir(const char *path, store_type_t type);
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path, store_type_t type);
crust_status_t ocall_save_file(const char *path, const unsigned char *data, size_t data_size, store_type_t type);
crust_status_t ocall_save_ipfs_block(const char *path, const uint8_t *data, size_t data_size, char *uuid, size_t uuid_len);
crust_status_t ocall_delete_folder_or_file(const char *path, store_type_t type);
crust_status_t ocall_delete_ipfs_file(const char *cid);
crust_status_t ocall_get_file(const char *path, unsigned char **p_file, size_t *len, store_type_t type);
void ocall_set_srd_info(const uint8_t *data, size_t data_size);
#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_STORE_OCALLS_H_ */
