#ifndef _OCALLS_APP_H_
#define _OCALLS_APP_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <string>
#include <vector>
#include "../Utils/FileUtils.h"
#include "../Utils/FormatUtils.h"
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

void ocall_save_file(const char *file_path, const char *data, const size_t *size)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    out.write(data, *size);
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



unsigned char *ocall_get_m_hashs(const char *path, const size_t *number)
{
    printf("PATH: %s\n", path);
    if (access(path, 0) == -1)
    {
        return NULL;
    }

    std::vector<std::string> files = get_files_under_path(std::string(path));
    if (*number != files.size())
    {
        return NULL;
    }

    unsigned char *hashs = new unsigned char[*number * 32];

    for (size_t i = 0; i < files.size(); i++)
    {
        hex_string_to_bytes(files[i].c_str() + files[i].size() - 64, hashs+ i * 32);
    }

    return hashs;
}

unsigned char *ocall_get_file(const char *file_path)
{
    return NULL;
}

#endif /* !_OCALLS_APP_H_ */
