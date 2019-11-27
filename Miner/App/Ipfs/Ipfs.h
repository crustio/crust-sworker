#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include "Node.h"

class Ipfs
{
private:
    Node* files;
    size_t files_num;
    size_t files_space_size;
    void clear_files();
public:
    Ipfs();
    ~Ipfs();
    Node* get_files();
    size_t get_files_num();
    size_t get_files_space_size();
    void get_merkle_tree(const char* root_cid);
    unsigned char* get_block_data(const char* cid, size_t *len);
};

#endif /* !_CRUST_APP_H_ */
