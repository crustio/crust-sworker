#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <map>
#include "Node.h"
#include "MerkleTree.h"

#include <cpprest/http_client.h>
#include <cpprest/json.h>

class Ipfs
{
private:
    Node *files;
    size_t files_num;
    size_t files_space_size;
    web::http::client::http_client *ipfs_client;
    unsigned char* block_data;
    MerkleTree *merkle_tree;
    void clear_merkle_tree(MerkleTree *&root);
    void clear_files();
    void clear_block_data();
    void fill_merkle_tree(MerkleTree *&root, const char *root_cid, web::json::array blocks_raw_array, std::map<std::string, size_t> blocks_map);
public:
    Ipfs(const char *url);
    ~Ipfs();
    Node *get_files();
    size_t get_files_num();
    size_t get_files_space_size();
    MerkleTree *get_merkle_tree(const char *root_cid);
    unsigned char *get_block_data(const char *cid, size_t *len);
    void set_ipfs_client_url(const char *url);
};

Ipfs *get_ipfs(const char *url);
Ipfs *get_ipfs();

#endif /* !_CRUST_APP_H_ */
