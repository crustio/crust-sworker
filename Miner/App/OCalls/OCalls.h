#ifndef _OCALLS_APP_H_
#define _OCALLS_APP_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <string>
#include <vector>
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

unsigned char *hex_char_array_to_unsigned_char_array(const char *data)
{
    std::string hex(data);
    unsigned char *result = new unsigned char[strlen(data) / 2];
    size_t len_t = 0;
    for (size_t i = 0; i < strlen(data); i += 2)
    {
        std::string byte = hex.substr(i, 2);
        char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
        result[len_t++] = (unsigned char)chr;
    }

    return result;
}

void ocall_save_file(const char *file_path, const char *data, const size_t *size)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    out.write(data, *size);
    out.close();
}

#endif /* !_OCALLS_APP_H_ */
