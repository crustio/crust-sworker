#include "Ipfs.h"

Ipfs *ipfs = NULL;

Ipfs *get_ipfs(const char *url)
{
    if(ipfs != NULL)
    {
       delete ipfs;
    }

    ipfs = new Ipfs(url);
    return ipfs;
}

Ipfs *get_ipfs()
{
    if(ipfs == NULL)
    {
        printf("Please use get_ipfs(url) frist.\n");
        exit(-1);
    }

    return ipfs;
}

Ipfs::Ipfs(const char *url)
{
    this->files = NULL;
    this->files_num = 0;
    this->files_space_size = 0;
    this->ipfs_client = new web::http::client::http_client(url);
}

Ipfs::~Ipfs()
{
    clear_files();
    delete this->ipfs_client;
}

void Ipfs::clear_files()
{
    if (this->files != NULL)
    {
        for (size_t i = 0; i < this->files_num; i++)
        {
            delete[] this->files[i].cid;
        }

        delete this->files;
        this->files = NULL;
        this->files_num = 0;
        this->files_space_size = 0;
    }
}

Node *Ipfs::get_files()
{
    this->clear_files();
    // TODO: get files from ipfs
    this->files_num = 2;
    this->files_space_size = 55 * 2;
    this->files = new Node[this->files_num];

    files[0].cid = strdup("QmT2vLA4N6L1c9SzG64PS4FZd87tS21Lo9yxaXYwdYpL67");
    files[0].size = 3246;
    files[1].cid = strdup("QmeZ5exiEb7d9RCMiwVBQFUPcQh5tvLaxgsUXi4iE2HPKE");
    files[1].size = 105;

    return files;
}

MerkleTree *Ipfs::get_merkle_tree(const char *root_cid)
{
    MerkleTree *root = new MerkleTree();
    root->cid = strdup(root_cid);
    root->size = 1000;
    root->children = NULL;
    return root;
}

unsigned char *Ipfs::get_block_data(const char *cid, size_t *len)
{
    return NULL;
}

size_t Ipfs::get_files_num()
{
    return this->files_num;
}

size_t Ipfs::get_files_space_size()
{
    return this->files_space_size;
}
