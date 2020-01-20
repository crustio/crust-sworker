#include "Ipfs.h"

extern FILE *felog;
Ipfs *ipfs = NULL;

/**
 * @description: new a global IPFS handler to access IPFS node
 * @param url -> ipfs API base url 
 * @return: the point of IPFS handler
 */
Ipfs *new_ipfs(const char *url)
{
    if (ipfs != NULL)
    {
        delete ipfs;
    }

    ipfs = new Ipfs(url);
    return ipfs;
}

/**
 * @description: get the global IPFS handler to access IPFS node 
 * @return: the point of IPFS handle
 */
Ipfs *get_ipfs(void)
{
    if (ipfs == NULL)
    {
        cfprintf(felog, CF_ERROR "Please use new_ipfs(url) frist.\n");
    }

    return ipfs;
}

/**
 * @description: Test if there is usable IPFS
 * @return: Test result
 * */
bool Ipfs::is_online()
{
    try
    {
        std::string path = this->url_end_point->base + "/work";
        auto res = this->crust_client->Get(path.c_str());
        if (res && res->status == 200)
        {
            return true;
        }

        return false;
    }
    catch (const std::exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
    }

    return false;
}

/**
 * @description: constructor
 * @param url -> API base url 
 */
Ipfs::Ipfs(const char *url)
{
    this->url_end_point = get_url_end_point(url);
    this->crust_client = new httplib::Client(this->url_end_point->ip, this->url_end_point->port);
    this->block_data = NULL;
    this->merkle_tree = NULL;
    this->files_a_is_old = true;
}

/**
 * @description: destructor
 */
Ipfs::~Ipfs()
{
    this->diff_files.clear();
    this->files_a.clear();
    this->files_b.clear();
    this->clear_block_data();
    this->clear_merkle_tree(this->merkle_tree);
}

/**
 * @description: release block_data
 */
void Ipfs::clear_block_data(void)
{
    if (this->block_data != NULL)
    {
        delete block_data;
        this->block_data = NULL;
    }
}

/**
 * @description: release merkle_tree
 * @param root -> the root of merkle tree 
 */
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

/**
 * @description: convert integer json array to byte vector
 * @param hash_array -> json array
 * @return: byte vector
 */
std::vector<unsigned char> Ipfs::get_hash_from_json_array(json::JSON hash_array)
{
    std::vector<unsigned char> result(hash_array.size());

    for (int i = 0; i < hash_array.size(); i++)
    {
        result[i] = (unsigned char)hash_array[i].ToInt();
    }

    return result;
}

/**
 * @description: create new byte vector from byte array
 * @param in -> byte vector
 * @return: byte array
 */
unsigned char *Ipfs::bytes_dup(std::vector<unsigned char> in)
{
    unsigned char *out = new unsigned char[in.size()];

    for (size_t i = 0; i < in.size(); i++)
    {
        out[i] = in[i];
    }

    return out;
}

/**
 * @description: release diff_files
 */
void Ipfs::clear_diff_files(void)
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

/**
 * @description: generate changed files
 * @return: whether the changed files is empty
 */
bool Ipfs::generate_diff_files(void)
{
    /* Get contain for storing files */
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

    std::string path = this->url_end_point->base + "/work";
    auto res = this->crust_client->Get(path.c_str());
    if (!res || res->status != 200)
    {
        return false;
    }

    json::JSON res_json = json::JSON::Load(res->body);
    json::JSON files_raw_array = res_json["Files"];

    /* Generate diff files */
    for (int i = 0; i < files_raw_array.size(); i++)
    {
        json::JSON file_raw = files_raw_array[i];
        std::vector<unsigned char> hash = get_hash_from_json_array(file_raw["Hash"]);
        size_t size = (size_t)file_raw["Size"].ToInt();

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

/**
 * @description: get changed files
 * @return: changed files
 */
Node *Ipfs::get_diff_files(void)
{
    return &this->diff_files[0];
}

/**
 * @description: get the number of changed files
 * @return: the number of changed files
 */
size_t Ipfs::get_diff_files_num(void)
{
    return this->diff_files.size();
}

/**
 * @description: populate merkle tree recursively with data
 * @param root -> the root of merkle tree
 * @param merkle_data -> merkle data of json format
 */
void Ipfs::fill_merkle_tree(MerkleTree *&root, json::JSON merkle_data)
{
    /* Fill root */
    root = new MerkleTree();
    root->hash = strdup(merkle_data["Hash"].ToString().c_str());
    root->size = merkle_data["Size"].ToInt();

    json::JSON links_array = merkle_data["Links"];
    root->links_num = links_array.size();
    if (root->links_num == 0)
    {
        root->links = NULL;
        return;
    }

    /* Fill links */
    root->links = new MerkleTree *[root->links_num];
    for (int i = 0; i < links_array.size(); i++)
    {
        this->fill_merkle_tree(root->links[i], links_array[i]);
    }
}

/**
 * @description: get merkle tree from ipfs by file root hash
 * @param root_hash -> the root hash of merkle tree
 * @return: whole merkle tree
 */
MerkleTree *Ipfs::get_merkle_tree(const char *root_hash)
{
    this->clear_merkle_tree(this->merkle_tree);
    std::string path = this->url_end_point->base + "/merkle?arg=" + root_hash;
    auto res = this->crust_client->Get(path.c_str());

    if (!res || res->status != 200)
    {
        return NULL;
    }
    json::JSON merkle_data = json::JSON::Load(res->body);
    this->fill_merkle_tree(this->merkle_tree, merkle_data);

    return this->merkle_tree;
}

/**
 * @description: get block data from ipfs by block hash
 * @param hash -> the block hash
 * @param len(out) -> the length of block data 
 * @return: the block data
 */
unsigned char *Ipfs::get_block_data(const char *hash, size_t *len)
{
    /* Get block data from ipfs */
    this->clear_block_data();

    std::string path = this->url_end_point->base + "/block/hashget?arg=" + hash;
    auto res = this->crust_client->Get(path.c_str());

    if (!res || res->status != 200)
    {
        return NULL;
    }

    std::vector<unsigned char> result = std::vector<unsigned char>(res->body.data(), res->body.data() + res->body.length());
    
    *len = result.size();
    this->block_data = new unsigned char[result.size()];
    for (size_t i = 0; i < result.size(); i++)
    {
        this->block_data[i] = result[i];
    }

    return this->block_data;
}
