#include "Common.h"
#include "Resource.h"

#define PRINT_BUF_SIZE  10000

using namespace std;

extern FILE *felog;
extern const char *g_show_tag;
char print_buf[PRINT_BUF_SIZE];

/**
 * @description: print messages to stderr. If specific stream defined
 *  output messages to it.
 * @return: print status
 * */
void _cprintf_real(FILE *stream, std::string info, const char *info_tag)
{
    // Print timestamp
    time_t ts;
    struct tm timetm, *timetmp;
    char timestr[TIMESTR_SIZE];
    time(&ts);
#ifndef _WIN32
    timetmp = localtime(&ts);
    if (timetmp == NULL)
    {
        perror("localtime");
        return;
    }
    timetm = *timetmp;
#else
    localtime_s(&timetm, &ts);
#endif

    /* If you change this format, you _may_ need to change TIMESTR_SIZE */
    if (strftime(timestr, TIMESTR_SIZE, "%b %e %Y %T", &timetm) == 0)
    {
        /* oops */
        timestr[0] = 0;
    }
    fprintf(stderr, "[%s] %s %s %s", timestr, info_tag, g_show_tag, info.c_str());

    // Print log to indicated stream
    if (stream != NULL)
    {
        if (!(info.size() == 1 && info[0] == '\n'))
        {
            fprintf(stream, "[%s] %s %s %s", timestr, info_tag, g_show_tag, info.c_str());
        }
        fflush(stream);
    }
}

/**
 * @description: Print info
 * */
void cprintf_info(FILE *stream, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    int n = vsnprintf(print_buf, PRINT_BUF_SIZE, format, va);
    va_end(va);

    std::string str(print_buf, n);

    _cprintf_real(stream, str, "[INFO]");
}

/**
 * @description: Print warning
 * */
void cprintf_warn(FILE *stream, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    int n = vsnprintf(print_buf, PRINT_BUF_SIZE, format, va);
    va_end(va);

    std::string str(print_buf, n);

    _cprintf_real(stream, str, "[WARN]");
}

/**
 * @description: Print error
 * */
void cprintf_err(FILE *stream, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    int n = vsnprintf(print_buf, PRINT_BUF_SIZE, format, va);
    va_end(va);

    std::string str(print_buf, n);

    _cprintf_real(stream, str, "[ERROR]");
}

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
    root->hash = (char*)malloc(HASH_LENGTH);
    memset(root->hash, 0, HASH_LENGTH);
    memcpy(root->hash, hash.c_str(), HASH_LENGTH);
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
