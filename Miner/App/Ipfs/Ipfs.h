#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <map>
#include <set>
#include <sys/time.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include "Node.h"
#include "MerkleTree.h"

class Ipfs
{
private:
    bool files_a_is_old;
    std::map<std::vector<unsigned char>, size_t> files_a;
    std::map<std::vector<unsigned char>, size_t> files_b;
    std::vector<Node> diff_files;
    web::http::client::http_client *ipfs_client;
    unsigned char *block_data;
    MerkleTree *merkle_tree;
    std::vector<unsigned char> get_hash_from_json_array(web::json::array hash_array);
    unsigned char *bytes_dup(std::vector<unsigned char> in);
    void clear_merkle_tree(MerkleTree *&root);
    void clear_block_data();
    void clear_diff_files();
    void fill_merkle_tree(MerkleTree *&root, web::json::value merkle_data);

public:
    Ipfs(const char *url);
    ~Ipfs();
    bool generate_diff_files();
    Node *get_diff_files();
    size_t get_diff_files_num();
    size_t get_diff_files_space_size();
    MerkleTree *get_merkle_tree(const char *root_hash);
    unsigned char *get_block_data(const char *hash, size_t *len);
    void set_ipfs_client_url(const char *url);
};

Ipfs *new_ipfs(const char *url);
Ipfs *get_ipfs();

#endif /* !_CRUST_IPFS_H_ */
