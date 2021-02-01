#ifndef _COMMON_H_
#define _COMMON_H_

/* Help keep our console messages clean and organzied */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include <boost/algorithm/string.hpp>

#include "Resource.h"
#include "FormatUtils.h"
#include "MerkleTree.h"
#include "Log.h"
#include "../enclave/utils/Json.h"

#if defined(__cplusplus)
extern "C"
{
#endif
    struct UrlEndPoint
    {
        std::string ip;
        std::string base;
        int port = -1;
    };

    UrlEndPoint get_url_end_point(std::string url);
    void remove_chars_from_string(std::string &str, const char *chars_to_remove);
    MerkleTree *deserialize_merkle_tree_from_json(json::JSON tree_json);
    json::JSON serialize_merkletree_to_json(MerkleTree *root);
    void free_merkletree(MerkleTree *root);
    std::string flat_urlformat(std::string &url);
    bool is_number(const std::string &s);
    void replace(std::string &data, std::string org_str, std::string det_str);
    void remove_char(std::string &data, char c);
    void srand_string(std::string seed);
    void print_attention();
    bool sleep_interval(uint32_t time, std::function<bool()> func);
    std::string float_to_string(double num);

#if defined(__cplusplus)
}
#endif

#endif
