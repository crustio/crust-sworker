#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <map>
#include <set>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include "Node.h"
#include "MerkleTree.h"

class Ipfs
{
private:
    std::map<std::string, size_t> files;
    std::vector<Node> diff_files;
    web::http::client::http_client *ipfs_client;
    unsigned char *block_data;
    MerkleTree *merkle_tree;
    void clear_merkle_tree(MerkleTree *&root);
    void clear_block_data();
    void fill_merkle_tree(MerkleTree *&root, const char *root_cid, web::json::array blocks_raw_array, std::map<std::string, size_t> blocks_map);

public:
    Ipfs(const char *url);
    ~Ipfs();
    bool generate_diff_files();
    Node *get_diff_files();
    size_t get_diff_files_num();
    size_t get_diff_files_space_size();
    MerkleTree *get_merkle_tree(const char *root_cid);
    unsigned char *get_block_data(const char *cid, size_t *len);
    void set_ipfs_client_url(const char *url);
};

Ipfs *new_ipfs(const char *url);
Ipfs *get_ipfs();

#endif /* !_CRUST_IPFS_H_ */
