#include "PathHelper.h"

/**
 * @description: get the path of m_hashs.bin
 * @param g_path -> the G path
 * @return: the m_hashs.bin path
 */
std::string get_m_hashs_file_path(const char *g_path)
{
    std::string file_path(g_path);
    file_path = file_path + '/' + PLOT_M_HASHS;
    return file_path;
}

/**
 * @description: get the path of the leaf file
 * @param g_path -> the G path
 * @param now_index -> the index of the leaf file
 * @param hash ->  the index of the leaf file
 * @return: the leaf file's path
 */
std::string get_leaf_path(const char *g_path, const size_t now_index, const unsigned char *hash)
{
    std::string leaf_path = std::string(g_path) + "/" + std::to_string(now_index + 1);
    return leaf_path + '-' + unsigned_char_array_to_hex_string(hash, 32);
}

/**
 * @description: get the G path by using hash
 * @param g_path -> the directory path
 * @param hash ->  the index of G folder
 * @return: the G path
 */
std::string get_g_path_with_hash(const char *dir_path, const unsigned char *hash)
{
    std::string g_path = std::string(dir_path) + "/";
    return g_path + '-' + unsigned_char_array_to_hex_string(hash, HASH_LENGTH);
}

/**
 * @description: get the G path
 * @param g_path -> the directory path
 * @param now_index -> the index of G folder
 * @return: the G path
 */
std::string get_g_path(const char *dir_path, const size_t now_index)
{
    return std::string(dir_path) + "/" + std::to_string(now_index + 1);
}
