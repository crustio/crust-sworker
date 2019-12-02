#include "Ipfs.h"

Ipfs *ipfs = NULL;

Ipfs *new_ipfs(const char *url)
{
    if (ipfs != NULL)
    {
        delete ipfs;
    }

    ipfs = new Ipfs(url);
    return ipfs;
}

Ipfs *get_ipfs()
{
    if (ipfs == NULL)
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
    this->block_data = NULL;
    this->merkle_tree = NULL;
    this->ipfs_client = new web::http::client::http_client(url);
}

Ipfs::~Ipfs()
{
    this->clear_files();
    this->clear_block_data();
    this->clear_merkle_tree(this->merkle_tree);
    delete this->ipfs_client;
}

void Ipfs::clear_block_data()
{
    if (this->block_data != NULL)
    {
        delete block_data;
        this->block_data = NULL;
    }
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

void Ipfs::clear_merkle_tree(MerkleTree *&root)
{
    if (root != NULL)
    {
        delete[] root->cid;
        if (root->links != NULL)
        {
            for (size_t i = 0; i < root->links_num; i++)
            {
                this->clear_merkle_tree(root->links[i]);
            }
            delete[] root->links;
            root->links = NULL;
        }
        delete root;
        root = NULL;
    }
}

Node *Ipfs::get_files()
{
    this->clear_files();
    web::uri_builder builder(U("/work"));
    web::http::http_response response = ipfs_client->request(web::http::methods::GET, builder.to_string()).get();

    if (response.status_code() != web::http::status_codes::OK)
    {
        return NULL;
    }

    std::string work_data = response.extract_utf8string().get();
    web::json::array files_raw_array = web::json::value::parse(work_data)["Files"].as_array();
    this->files_num = files_raw_array.size();
    this->files_space_size = this->files_num * NODE_STRUCT_SPACE;
    this->files = new Node[this->files_num];

    for (size_t i = 0; i < this->files_num; i++)
    {
        web::json::value file_raw = files_raw_array[i];
        files[i].cid = strdup(file_raw["Cid"].as_string().c_str());
        files[i].size = file_raw["Size"].as_integer();
    }

    return this->files;
}

void Ipfs::fill_merkle_tree(MerkleTree *&root, const char *root_cid, web::json::array blocks_raw_array, std::map<std::string, size_t> blocks_map)
{
    root = new MerkleTree();
    root->cid = strdup(blocks_raw_array[blocks_map[root_cid]]["Cid"].as_string().c_str());
    root->size = blocks_raw_array[blocks_map[root_cid]]["Size"].as_integer();

    web::json::array links_array = blocks_raw_array[blocks_map[root_cid]]["Links"].as_array();
    root->links_num = links_array.size();
    if (root->links_num == 0)
    {
        root->links = NULL;
        return;
    }

    root->links = new MerkleTree *[root->links_num];

    for (size_t i = 0; i < links_array.size(); i++)
    {
        this->fill_merkle_tree(root->links[i], links_array[i].as_string().c_str(), blocks_raw_array, blocks_map);
    }
}

MerkleTree *Ipfs::get_merkle_tree(const char *root_cid)
{
    this->clear_merkle_tree(this->merkle_tree);
    web::uri_builder builder(U("/merkle"));
    builder.append_query(U("arg"), U(root_cid));
    web::http::http_response response = ipfs_client->request(web::http::methods::GET, builder.to_string()).get();

    if (response.status_code() != web::http::status_codes::OK)
    {
        return NULL;
    }

    std::string merkle_data = response.extract_utf8string().get();
    web::json::array blocks_raw_array = web::json::value::parse(merkle_data)["Blocks"].as_array();
    std::map<std::string, size_t> blocks_map;

    for (size_t i = 0; i < blocks_raw_array.size(); i++)
    {
        blocks_map.insert(std::pair<std::string, size_t>(blocks_raw_array[i]["Cid"].as_string(), i));
    }

    this->fill_merkle_tree(this->merkle_tree, root_cid, blocks_raw_array, blocks_map);
    return this->merkle_tree;
}

unsigned char *Ipfs::get_block_data(const char *cid, size_t *len)
{
    this->clear_block_data();
    web::uri_builder builder(U("/block/get"));
    builder.append_query(U("arg"), U(cid));
    web::http::http_response response = ipfs_client->request(web::http::methods::GET, builder.to_string()).get();

    if (response.status_code() != web::http::status_codes::OK)
    {
        return NULL;
    }

    std::vector<unsigned char> result = response.extract_vector().get();
    *len = result.size();
    this->block_data = new unsigned char[result.size()];
    for (size_t i = 0; i < result.size(); i++)
    {
        this->block_data[i] = result[i];
    }

    return this->block_data;
}

size_t Ipfs::get_files_num()
{
    return this->files_num;
}

size_t Ipfs::get_files_space_size()
{
    return this->files_space_size;
}
