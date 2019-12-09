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
    this->block_data = NULL;
    this->merkle_tree = NULL;
    this->ipfs_client = new web::http::client::http_client(url);
    this->files_a_is_old = true;
}

Ipfs::~Ipfs()
{
    this->diff_files.clear();
    this->files_a.clear();
    this->files_b.clear();
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

void Ipfs::clear_merkle_tree(MerkleTree *&root)
{
    if (root != NULL)
    {
        delete[] root->hash;
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

std::vector<unsigned char> Ipfs::get_hash_from_json_array(web::json::array hash_array)
{
    std::vector<unsigned char> result(hash_array.size());

    for (size_t i = 0; i < hash_array.size(); i++)
    {
        result[i] = (unsigned char)hash_array[i].as_integer();
    }

    return result;
}

unsigned char *Ipfs::bytes_dup(std::vector<unsigned char> in)
{
    unsigned char *out = new unsigned char[in.size()];

    for (size_t i = 0; i < in.size(); i++)
    {
        out[i] = in[i];
    }

    return out;
}

void Ipfs::clear_diff_files()
{
    if (!this->diff_files.empty())
    {
        for (size_t i = 0; i < this->diff_files.size(); i++)
        {
            delete[] this->diff_files[i].hash;
        }

        diff_files.clear();
    }
}

bool Ipfs::generate_diff_files()
{
    // Get contain for storing files
    this->clear_diff_files();
    std::map<std::vector<unsigned char>, size_t> *new_files;
    std::map<std::vector<unsigned char>, size_t> *old_files;

    if (this->files_a_is_old)
    {
        new_files = &this->files_b;
        old_files = &this->files_a;
    }
    else
    {
        new_files = &this->files_a;
        old_files = &this->files_b;
    }

    new_files->clear();
    this->files_a_is_old = !this->files_a_is_old;

    // Get work from ipfs
    web::uri_builder builder(U("/work"));
    web::http::http_response response = ipfs_client->request(web::http::methods::GET, builder.to_string()).get();

    if (response.status_code() != web::http::status_codes::OK)
    {
        return false;
    }

    std::string work_data = response.extract_utf8string().get();
    web::json::array files_raw_array = web::json::value::parse(work_data)["Files"].as_array();

    // Generate diff files
    for (size_t i = 0; i < files_raw_array.size(); i++)
    {
        web::json::value file_raw = files_raw_array[i];
        std::vector<unsigned char> hash = get_hash_from_json_array(file_raw["Hash"].as_array());
        size_t size = (size_t)file_raw["Size"].as_integer();

        new_files->insert(std::pair<std::vector<unsigned char>, size_t>(hash, size));
        if (old_files->find(hash) == old_files->end())
        {
            Node node;
            node.hash = bytes_dup(hash);
            node.size = size;
            node.exist = 1;
            this->diff_files.push_back(node);
            old_files->insert(std::pair<std::vector<unsigned char>, size_t>(hash, size));
        }
    }

    for (auto it = old_files->begin(); it != old_files->end(); it++)
    {
        if (new_files->find(it->first) == new_files->end())
        {
            Node node;
            node.hash = bytes_dup(it->first);
            node.size = it->second;
            node.exist = 0;
            this->diff_files.push_back(node);
        }
    }

    return !this->diff_files.empty();
}

Node *Ipfs::get_diff_files()
{
    return &this->diff_files[0];
}

size_t Ipfs::get_diff_files_num()
{
    return this->diff_files.size();
}

size_t Ipfs::get_diff_files_space_size()
{
    return this->diff_files.size() * NODE_STRUCT_SPACE;
}

void Ipfs::fill_merkle_tree(MerkleTree *&root, web::json::value merkle_data)
{
    root = new MerkleTree();
    root->hash = strdup(merkle_data["Hash"].as_string().c_str());
    root->size = merkle_data["Size"].as_integer();

    web::json::array links_array = merkle_data["Links"].as_array();
    root->links_num = links_array.size();
    if (root->links_num == 0)
    {
        root->links = NULL;
        return;
    }

    root->links = new MerkleTree *[root->links_num];

    for (size_t i = 0; i < links_array.size(); i++)
    {
        this->fill_merkle_tree(root->links[i], links_array[i]);
    }
}

MerkleTree *Ipfs::get_merkle_tree(const char *root_hash)
{
    this->clear_merkle_tree(this->merkle_tree);
    web::uri_builder builder(U("/merkle"));
    builder.append_query(U("arg"), U(root_hash));
    web::http::http_response response = ipfs_client->request(web::http::methods::GET, builder.to_string()).get();

    if (response.status_code() != web::http::status_codes::OK)
    {
        return NULL;
    }

    web::json::value merkle_data = response.extract_json().get();
    this->fill_merkle_tree(this->merkle_tree, merkle_data);

    return this->merkle_tree;
}

unsigned char *Ipfs::get_block_data(const char *hash, size_t *len)
{
    this->clear_block_data();
    web::uri_builder builder(U("/block/hashget"));
    builder.append_query(U("arg"), U(hash));
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
