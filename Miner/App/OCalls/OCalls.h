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

    printf("Store files into: '%s'\n", path);
}

std::string hash_to_hex_string(const unsigned char *hash)
{
    char *hex_char_array = new char[65];

    for (size_t i = 0; i < 32; i++)
    {
        char temp[3];
        sprintf(temp, "%02x", hash[i]);
        hex_char_array[i * 2] = temp[0];
        hex_char_array[i * 2 + 1] = temp[1];
    }

    hex_char_array[64] = '\0';
    std::string hex_string(hex_char_array);
    delete[] hex_char_array;

    return hex_string;
}

void ocall_save_file(const char *path, const unsigned char *hash, const size_t *index, const unsigned char *data, const size_t *size)
{
    std::string file_path(path);
    std::string hex_string = hash_to_hex_string(hash);
    file_path += '/' + std::to_string(*index) + '-' + hex_string;
    printf("Into: %s\n", file_path.c_str());

    unsigned char *data_out = new unsigned char[*size];

    for (size_t i = 0; i < *size; i++)
    {
        printf("%02x", data[i]);
        data_out[i] = data[i];
    }
    printf("\n");

    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    out.write(reinterpret_cast<char *>(data_out), *size);
    out.close();

    delete[] data_out;
}

#endif /* !_OCALLS_APP_H_ */