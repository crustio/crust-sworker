#include "PathHelper.h"

std::string get_m_hashs_file_path(const char *g_path)
{
    std::string file_path(g_path);
    file_path = file_path + '/' + PLOT_M_HASHS;
    return file_path;
}

std::string get_leaf_path(const char *g_path, const size_t now_index, const unsigned char *hash)
{
    std::string leaf_path = std::string(g_path) + "/" + std::to_string(now_index + 1);
    return leaf_path + '-' + unsigned_char_array_to_hex_string(hash, 32);
}

std::string get_g_path_with_hash(const char *dir_path, const size_t now_index, const unsigned char *hash)
{
    std::string g_path = std::string(dir_path) + "/" + std::to_string(now_index + 1);
    return g_path + '-' + unsigned_char_array_to_hex_string(hash, 32);
}

std::string get_g_path(const char *dir_path, const size_t now_index)
{
    return std::string(dir_path) + "/" + std::to_string(now_index + 1);
}
