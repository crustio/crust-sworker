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
#include "Ipfs.h"
#include "FileUtils.h"
#include "FormatUtils.h"
#include "Common.h"
#include "Log.h"
#include "CrustStatus.h"

#if defined(__cplusplus)
extern "C"
{
#endif

    void ocall_print_string(const char *str);
    void ocall_eprint_string(const char *str);
    void ocall_create_dir(const char *path);
    void ocall_rename_dir(const char *old_path, const char *new_path);
    void ocall_save_file(const char *file_path, const unsigned char *data, size_t len);
    size_t ocall_get_folders_number_under_path(const char *path);
    void ocall_delete_folder_or_file(const char *path);
    void ocall_get_file(const char *file_path, unsigned char **p_file, size_t *len);
    void ocall_get_merkle_tree(const char *root_hash, MerkleTree **p_merkletree);
    void ocall_get_block(const char *hash, size_t *len, unsigned char **p_block);
    void ocall_get_diff_files(Node **node);
    size_t ocall_get_diff_files_num();
    void ocall_usleep(int u);
    crust_status_t ocall_get_file_block_by_path(char *root_hash, char *cur_hash, uint32_t hash_len, uint32_t *path, uint32_t path_count);

#if defined(__cplusplus)
}
#endif

#endif /* !_OCALLS_APP_H_ */
