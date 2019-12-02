#ifndef _CRUST_CONFIG_H_
#define _CRUST_CONFIG_H_

#include <stdio.h>
#include <string>
#include <fstream>
#include <cpprest/json.h>

class Config
{
public:
    std::string empty_path;
    size_t empty_capacity;
    std::string ipfs_api_base_url;
    Config(std::string path);
    void show();
};

Config *new_config(const char *path);
Config *get_config();

#endif /* !_CRUST_CONFIG_H_ */
