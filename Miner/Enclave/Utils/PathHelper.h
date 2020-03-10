#ifndef _CRUST_PATH_HELPER_H_
#define _CRUST_PATH_HELPER_H_

#include <string>
#include "EUtils.h"

std::string get_g_path(const char *dir_path, const size_t now_index);
std::string get_leaf_path(const char *g_path, const size_t now_index, const unsigned char *hash);
std::string get_g_path_with_hash(const char *dir_path, const size_t now_index, const unsigned char *hash);
std::string get_m_hashs_file_path(const char *g_path);

#endif /* !_CRUST_PATH_HELPER_H_ */
