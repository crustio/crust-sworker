#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
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
    void clear_files();

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
