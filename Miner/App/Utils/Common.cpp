#include "Common.h"
#include "Resource.h"
#include "FormatUtils.h"

/**
 * @description: get url end point from url
 * @param url base url, like: http://127.0.0.1:56666/api/v1
 * @return: url end point
 * */
UrlEndPoint *get_url_end_point(std::string url)
{
    std::vector<std::string> fields;
    boost::split(fields, url, boost::is_any_of(":"));
    UrlEndPoint *url_end_point = new UrlEndPoint();
    url_end_point->ip = fields[1].substr(2);

    std::vector<std::string> fields2;
    boost::split(fields2, fields[2], boost::is_any_of("/"));

    url_end_point->port = std::stoi(fields2[0]);
    url_end_point->base = "";
    for (size_t i = 1; i < fields2.size(); i++)
    {
        url_end_point->base += "/" + fields2[i];
    }

    return url_end_point;
}

/**
 * @description: remove chars from string
 * @param str input string
 * @param chars_to_remove removed chars
 * */
void remove_chars_from_string(std::string &str, const char *chars_to_remove)
{
    for (unsigned int i = 0; i < strlen(chars_to_remove); ++i)
    {
        str.erase(std::remove(str.begin(), str.end(), chars_to_remove[i]), str.end());
    }
}

/**
 * @description: Deserialize merkle tree from json
 * @param tree_json -> Merkle tree json
 * @return: Merkle tree root node
 * */
MerkleTree *deserialize_merkle_tree_from_json(json::JSON tree_json)
{
    MerkleTree *root = new MerkleTree();
    string hash = tree_json["hash"].ToString();
    root->hash = (char*)hex_string_to_bytes(hash.c_str(), hash.size());
    root->links_num = tree_json["links_num"].ToInt();
    json::JSON children = tree_json["links"];

    if (root->links_num != 0)
    {
        root->links = (MerkleTree**)malloc(root->links_num * sizeof(MerkleTree*));
    }

    for (uint32_t i = 0; i < root->links_num; i++)
    {
        MerkleTree *child = deserialize_merkle_tree_from_json(children[i]);
        root->links[i] = child;
    }

    return root;
}
