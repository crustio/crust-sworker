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
#include "../Utils/FileUtils.h"
#include "../Utils/FormatUtils.h"
#include "../Ipfs/Ipfs.h"
#include <boost/algorithm/string.hpp>

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

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

void ocall_rename_dir(const char *old_path, const char *new_path)
{
    if (access(old_path, 0) != -1)
    {
        rename(old_path, new_path);
    }
}

void ocall_save_file(const char *file_path, const unsigned char *data, size_t len)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    out.write(reinterpret_cast<const char *>(data), len);
    out.close();
}

void ocall_get_folders_number_under_path(const char *path, size_t *number)
{
    if (access(path, 0) != -1)
    {
        *number = get_folders_under_path(std::string(path)).size();
    }
    else
    {
        *number = 0;
    }
}

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

MerkleTree *ocall_get_merkle_tree(const char *root_cid)
{
    return get_ipfs()->get_merkle_tree(root_cid);
}

unsigned char *ocall_get_block(const char *cid, size_t *len)
{
    return get_ipfs()->get_block_data(cid, len);
}

Node *ocall_get_diff_files()
{
    get_ipfs()->generate_diff_files();
    return get_ipfs()->get_diff_files();
}

size_t ocall_get_diff_files_num()
{
    return get_ipfs()->get_diff_files_num();
}

void ocall_usleep(int u)
{
    usleep(u);
}

#endif /* !_OCALLS_APP_H_ */
