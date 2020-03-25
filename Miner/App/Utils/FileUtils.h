#ifndef _CRUST_FILE_UTILS_H_
#define _CRUST_FILE_UTILS_H_

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <vector>
#include <string.h>

std::vector<std::string> get_files_under_path(std::string path);
std::vector<std::string> get_folders_under_path(std::string path);
int rm_dir(std::string dir_full_path);
int rm(std::string path);

#endif /* !_CRUST_FILE_UTILS_H_ */
