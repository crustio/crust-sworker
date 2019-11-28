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
    web::uri_builder builder(U("/work"));
    web::http::http_response response = ipfs_client->request(web::http::methods::GET, builder.to_string()).get();
    
    if(response.status_code() != web::http::status_codes::OK)
    {
        return NULL;
    }

    std::string work_data = response.extract_utf8string().get();
    web::json::value work = web::json::value::parse(work_data);
    web::json::array filesRawArray = work["Files"].as_array();
    this->files_num = filesRawArray.size();
    this->files_space_size = this->files_num * NODE_STRUCT_SPACE;
    this->files = new Node[this->files_num];

    for (size_t i = 0; i < this->files_num; i++)
	{
		web::json::value fileRaw = filesRawArray[i];
        files[i].cid = strdup(fileRaw["Cid"].as_string().c_str());
        files[i].size = fileRaw["Size"].as_integer();
	}

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
