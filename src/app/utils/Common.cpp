#include "Common.h"
#include "Resource.h"
#include "FormatUtils.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: get url end point from url
 * @param url base url, like: http://127.0.0.1:56666/api/v1
 * @return: url end point
 * */
UrlEndPoint *get_url_end_point(std::string url)
{
    UrlEndPoint *url_end_point = new UrlEndPoint();
    std::string proto_type;
    size_t spos = 0, epos;

    // Get protocal tag
    epos = url.find("://");
    if (epos != url.npos)
    {
        proto_type = url.substr(0, epos);
        spos = epos + std::strlen("://");
    }

    // Get host, port and path
    epos = url.find(":", spos);
    if (epos == url.npos)
    {
        epos = url.find("/", spos);
        url_end_point->ip = url.substr(spos, epos - spos);
        url_end_point->base = url.substr(epos, url.size());
        p_log->warn("Parse url warn: Port not indicate, will assign port by protocol.\n");
        if (proto_type.compare("https") == 0)
        {
            url_end_point->port = 443;
        }
        else if (proto_type.compare("http") == 0)
        {
            url_end_point->port = 80;
        }
        else
        {
            p_log->warn("Parse url warn: Cannot assign port by protocal!\n");
        }
        p_log->info("Parse url warn: Set port to:%d\n", url_end_point->port);
    }
    else
    {
        url_end_point->ip = url.substr(spos, epos - spos);
        spos = epos + 1;
        epos = url.find("/", spos);
        url_end_point->port = std::atoi(url.substr(spos, epos - spos).c_str());
        url_end_point->base = url.substr(epos, url.size());
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
    if (tree_json.JSONType() != json::JSON::Class::Object)
        return NULL;

    MerkleTree *root = new MerkleTree();
    std::string hash = tree_json["hash"].ToString();
    size_t hash_len = hash.size() + 1;
    root->hash = (char*)malloc(hash_len);
    memset(root->hash, 0, hash_len);
    memcpy(root->hash, hash.c_str(), hash.size());
    root->links_num = tree_json["links_num"].ToInt();
    json::JSON children = tree_json["links"];

    if (root->links_num != 0)
    {
        root->links = (MerkleTree**)malloc(root->links_num * sizeof(MerkleTree*));
        for (uint32_t i = 0; i < root->links_num; i++)
        {
            MerkleTree *child = deserialize_merkle_tree_from_json(children[i]);
            if (child == NULL)
            {
                free(root->hash);
                free(root->links);
                return NULL;
            }
            root->links[i] = child;
        }
    }

    return root;
}

/**
 * @description: Serialize MerkleTree to json
 * @param root -> MerkleTree root node
 * @return: MerkleTree json structure
 * */
json::JSON serialize_merkletree_to_json(MerkleTree *root)
{
    if (root == NULL)
        return "";

    json::JSON tree;
    tree["hash"] = std::string(root->hash);
    tree["links_num"] = root->links_num;
    for (size_t i = 0; i < root->links_num; i++)
    {
        tree["links"][i] = serialize_merkletree_to_json(root->links[i]);
    }

    return tree;
}
