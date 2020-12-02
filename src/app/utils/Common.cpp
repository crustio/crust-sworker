#include "Common.h"
#include "Resource.h"
#include "FormatUtils.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Get url end point from url
 * @param url -> base url, like: http://127.0.0.1:56666/api/v1
 * @return: Url end point
 */
UrlEndPoint get_url_end_point(std::string url)
{
    UrlEndPoint url_end_point;
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
        if (epos == url.npos)
        {
            url_end_point.ip = url.substr(spos, url.length());
            goto parse_end;
        }
        url_end_point.ip = url.substr(spos, epos - spos);
        url_end_point.base = url.substr(epos, url.size());
        p_log->warn("Parse url warn: Port not indicate, will assign port by protocol.\n");
        if (proto_type.compare("https") == 0)
        {
            url_end_point.port = 443;
        }
        else if (proto_type.compare("http") == 0)
        {
            url_end_point.port = 80;
        }
        else
        {
            p_log->warn("Parse url warn: Cannot assign port by protocal!\n");
        }
        p_log->info("Parse url warn: Set port to:%d\n", url_end_point.port);
    }
    else
    {
        url_end_point.ip = url.substr(spos, epos - spos);
        spos = epos + 1;
        epos = url.find("/", spos);
        if (epos == url.npos)
        {
            url_end_point.port = std::atoi(url.substr(spos, epos - spos).c_str());
            goto parse_end;
        }
        url_end_point.port = std::atoi(url.substr(spos, epos - spos).c_str());
        url_end_point.base = url.substr(epos, url.size());
    }

parse_end:

    return url_end_point;
}

/**
 * @description: Remove chars from string
 * @param str -> input string
 * @param chars_to_remove -> removed chars
 */
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
 */
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
 */
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

/**
 * @description: Free MerkleTree buffer
 * @param root -> Pointer to MerkleTree root
 */
void free_merkletree(MerkleTree *root)
{
    if (root == NULL)
        return;

    free(root->hash);

    if (root->links_num > 0)
    {
        for (size_t i = 0; i < root->links_num; i++)
        {
            free_merkletree(root->links[i]);
        }
        free(root->links);
    }
}

/**
 * @description: Hex string to int
 * @param s -> Pointer to hex char array
 * @return: Int
 */
static inline int htoi(char *s)
{
    int value;
    int c;

    c = ((unsigned char *)s)[0];
    if (isupper(c))
        c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char *)s)[1];
    if (isupper(c))
        c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

    return (value);
}

/**
 * @description: Decode url to flat string
 * @param url -> Reference to url
 * @return: Decoded url
 */
std::string flat_urlformat(std::string &url)
{
    int len = url.size();
    char *dest = (char*)malloc(url.size());
    memset(dest, 0, url.size());
    char *org = dest;

    int i = 0;
    while (len-- >= 0)
    {
        if (url[i] == '+')
        {
            *dest = ' ';
        }
        else if (url[i] == '%' && len >= 2 
                && isxdigit((int) url[i + 1])
                && isxdigit((int) url[i + 2])) 
        {
            *dest = (char) htoi(&url[i + 1]);
            i += 2;
            len -= 2;
        }
        else
        {
            *dest = url[i];
        }
        i++;
        dest++;
    }
    *dest = '\0';

    return std::string(org, dest - org);
}

/**
 * @description: Judge if a string is a number
 * @param s -> Const reference to string
 * @return: Number or not
 */
bool is_number(const std::string &s)
{
    for (auto c : s)
    {
        if (!isxdigit(c))
        {
            return false;
        }
    }

    return true;
}

/**
 * @description: Replace org_str to det_str in data
 * @param data -> Reference to origin data
 * @param org_str -> Replaced string
 * @param det_str -> Replaced to string
 */
void replace(std::string &data, std::string org_str, std::string det_str)
{
    size_t spos, epos;
    spos = epos = 0;

    while (true)
    {
        spos = data.find(org_str, epos);
        if (spos == data.npos)
        {
            break;
        }
        data.replace(spos, org_str.size(), det_str);
        epos = spos + det_str.size();
    }
}

/**
 * @description: Remove indicated character from string
 * @param data -> Reference to string
 * @param c -> Character to be removed
 * */
void remove_char(std::string &data, char c)
{
    data.erase(std::remove(data.begin(), data.end(), c), data.end());
}

/**
 * @description: Use string to set srand
 * @param seed -> random seed
 */
void srand_string(std::string seed)
{
    unsigned int seed_number = 0;
    for (size_t i = 0; i < seed.size(); i++)
    {
        seed_number += seed[i]*(i+1);
    }

    srand(time(NULL) + seed_number);
}

/**
 * @description: Print attention logo
 */
void print_attention()
{
    std::string gap = std::string(PRINT_GAP, ' ');
    std::string attention = ATTENTION_LOGO;
    replace(attention, "%", "\\");
    replace(attention, "\n", "\n" + gap);
    attention = HRED + gap + attention + NC;
    printf("\n%s\n", attention.c_str());
}
