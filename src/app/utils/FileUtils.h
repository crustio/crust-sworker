#ifndef _CRUST_FILE_UTILS_H_
#define _CRUST_FILE_UTILS_H_

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <vector>
#include <unordered_map>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <errno.h>
#include <sys/types.h>
#include "Config.h"
#include "DataBase.h"
#include "Json.hpp"

std::vector<std::string> get_files_under_path(std::string path);
std::vector<std::string> get_folders_under_path(std::string path);
int rm_dir(std::string dir_full_path);
int rm(std::string path);
size_t get_free_space_under_directory(std::string path);
bool create_directory(std::string path);
std::vector<std::string> get_sub_folders_and_files(const char *path);
crust_status_t get_file(const char *path, uint8_t **p_data, size_t *data_size);
size_t get_total_space_under_dir_k(std::string path);
size_t get_total_space_under_dir_m(std::string path);
size_t get_total_space_under_dir_g(std::string path);
size_t get_avail_space_under_dir_k(std::string path);
size_t get_avail_space_under_dir_m(std::string path);
size_t get_avail_space_under_dir_g(std::string path);

#endif /* !_CRUST_FILE_UTILS_H_ */
