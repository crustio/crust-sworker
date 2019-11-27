#include "Ipfs.h"

Ipfs::Ipfs()
{
    this->files = NULL;
    this->files_num = 0;
    this->files_space_size = 0;
}

Ipfs::~Ipfs()
{
    clear_files();
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

size_t Ipfs::get_files_num()
{
    return this->files_num;
}

size_t Ipfs::get_files_space_size()
{
    return this->files_space_size;
}
