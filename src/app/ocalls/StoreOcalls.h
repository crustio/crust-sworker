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
crust_status_t ocall_create_dir(const char *path);
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path);
crust_status_t ocall_save_file(const char *file_path, const unsigned char *data, size_t len);
crust_status_t ocall_delete_folder_or_file(const char *path);
crust_status_t ocall_get_file(const char *file_path, unsigned char **p_file, size_t *len);
#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_STORE_OCALLS_H_ */