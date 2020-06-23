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
#include "MerkleTree.h"
#include "Json.hpp"
#include "Log.h"

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

    UrlEndPoint *get_url_end_point(std::string url);
    void remove_chars_from_string(std::string &str, const char *chars_to_remove);
    MerkleTree *deserialize_merkle_tree_from_json(json::JSON tree_json);
    json::JSON serialize_merkletree_to_json(MerkleTree *root);
    void free_merkletree(MerkleTree *root);
    std::string flat_urlformat(std::string &url);

#if defined(__cplusplus)
}
#endif

#endif
