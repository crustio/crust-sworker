#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <map>
#include <set>
#include <sys/time.h>
#include "Node.h"
#include "MerkleTree.h"
#include "Common.h"
#include "HttpLib.h"
#include "Json.hpp"

class Ipfs
{
private:
    std::map<std::vector<unsigned char>, size_t> files_a; /* Used to store files' hash and size */
    std::map<std::vector<unsigned char>, size_t> files_b; /* Used to store files' hash and size */
    bool files_a_is_old;                                  /* Indicate who is old in files_a and files_b */
    std::vector<Node> diff_files;                         /* Confirm changed files by comparing files_a and files_b */
    unsigned char *block_data;                            /* Used to store block data */
    MerkleTree *merkle_tree;                              /* Used to store merkle tree of a file*/

    UrlEndPoint *url_end_point;    /* Url end point info */
    httplib::Client *crust_client; /* Used to call Crust API */

    std::vector<unsigned char> get_hash_from_json_array(json::JSON hash_array);
    unsigned char *bytes_dup(std::vector<unsigned char> in);
    void clear_merkle_tree(MerkleTree *&root);
    void clear_block_data(void);
    void clear_diff_files(void);
    void fill_merkle_tree(MerkleTree *&root, json::JSON merkle_data);

public:
    Ipfs(const char *url);
    ~Ipfs();
    bool is_online();
    bool generate_diff_files(void);
    Node *get_diff_files(void);
    size_t get_diff_files_num(void);
    MerkleTree *get_merkle_tree(const char *root_hash);
    unsigned char *get_block_data(const char *hash, size_t *len);
    void set_ipfs_client_url(const char *url);
};

Ipfs *new_ipfs(const char *url);
Ipfs *get_ipfs(void);

#endif /* !_CRUST_IPFS_H_ */
