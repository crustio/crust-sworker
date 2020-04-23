#ifndef __COMMON_H
#define __COMMON_H

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
#include "MerkleTree.h"
#include "Json.hpp"

#if defined(__cplusplus)
extern "C"
{
#endif
    struct UrlEndPoint
    {
        std::string ip;
        std::string base;
        int port;
    };

    UrlEndPoint *get_url_end_point(std::string url);
    void remove_chars_from_string(std::string &str, const char *chars_to_remove);
    MerkleTree *deserialize_merkle_tree_from_json(json::JSON tree_json);

#if defined(__cplusplus)
}
#endif

#endif
