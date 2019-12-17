#ifndef _OCALLS_APP_H_
#define _OCALLS_APP_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include "../Ipfs/Ipfs.h"
#include "../Utils/FileUtils.h"

/**
 * @description: ocall for printing string
 * @param str -> string for printing
 */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/**
 * @description: ocall for creating directory
 * @param path -> the path of directory
 */
void ocall_create_dir(const char *path)
{
    std::vector<std::string> fields;
    boost::split(fields, path, boost::is_any_of("/"));
    std::string current_path = "";

    for (size_t i = 0; i < fields.size(); i++)
    {
        if (access((current_path + fields[i]).c_str(), 0) == -1)
        {
            mkdir((current_path + fields[i]).c_str(), S_IRWXU);
        }

        current_path += fields[i] + "/";
    }
}

/**
 * @description: ocall for renaming directory
 * @param old_path -> the old path of directory
 * @param new_path -> the new path of directory
 */
void ocall_rename_dir(const char *old_path, const char *new_path)
{
    if (access(old_path, 0) != -1)
    {
        rename(old_path, new_path);
    }
}

/**
 * @description: ocall for saving data into file
 * @param file_path -> file path for saving
 * @param data -> data for saving
 * @param len -> the length of data
 */
void ocall_save_file(const char *file_path, const unsigned char *data, size_t len)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    out.write(reinterpret_cast<const char *>(data), len);
    out.close();
}

/**
 * @description: ocall for geting folders number under directory
 * @param path -> the path of directory
 * @return the number of folders
 */
size_t ocall_get_folders_number_under_path(const char *path)
{
    if (access(path, 0) != -1)
    {
        return get_folders_under_path(std::string(path)).size();
    }
    else
    {
        return 0;
    }
}

/**
 * @description: ocall for getting file
 * @param path -> the path of file
 * @param len -> the length of data
 * @return file data
 */
unsigned char *ocall_get_file(const char *file_path, size_t len)
{
    if (access(file_path, 0) == -1)
    {
        return NULL;
    }

    unsigned char *data = new unsigned char[len];
    std::ifstream in;

    in.open(file_path, std::ios::out | std::ios::binary);
    in.read(reinterpret_cast<char *>(data), len);
    in.close();

    return data;
}

/**
 * @description: ocall for getting merkle tree by root hash
 * @param root_hash -> the root hash of file
 * @return: the merkle tree of file
 */
MerkleTree *ocall_get_merkle_tree(const char *root_hash)
{
    return get_ipfs()->get_merkle_tree(root_hash);
}

/**
 * @description: ocall for getting block data from ipfs by block hash
 * @param hash -> the block hash
 * @param len(out) -> the length of block data 
 * @return: the block data
 */
unsigned char *ocall_get_block(const char *hash, size_t *len)
{
    return get_ipfs()->get_block_data(hash, len);
}

/**
 * @description: ocall for getting changed files
 * @return: changed files
 */
Node *ocall_get_diff_files()
{
    get_ipfs()->generate_diff_files();
    return get_ipfs()->get_diff_files();
}

/**
 * @description: ocall for getting the number of changed files
 * @return: the number of changed files
 */
size_t ocall_get_diff_files_num()
{
    return get_ipfs()->get_diff_files_num();
}

/**
 * @description: ocall for wait
 * @param u microsecond
 */
void ocall_usleep(int u)
{
    usleep(u);
}

#endif /* !_OCALLS_APP_H_ */
