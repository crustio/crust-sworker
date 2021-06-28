#include "Ipfs.h"

crust::Log *p_log = crust::Log::get_instance();
HttpClient *ipfs_client = NULL;
Ipfs *Ipfs::ipfs = NULL;
std::mutex ipfs_mutex;

const std::string block_get_timeout = "1s";
const std::string cat_timeout = "6s";
const std::string add_timeout = "600s";

/**
 * @desination: single instance class function to get instance
 * @return: ipfs instance
 */
Ipfs *Ipfs::get_instance()
{
    if (Ipfs::ipfs == NULL)
    {
        Config *p_config = Config::get_instance();
        ipfs_mutex.lock();
        if (Ipfs::ipfs == NULL)
        {
            Ipfs::ipfs = new Ipfs(p_config->ipfs_url);
        }
        ipfs_mutex.unlock();
    }

    return Ipfs::ipfs;
}

/**
 * @description: constructor
 * @param url -> API base url 
 */
Ipfs::Ipfs(std::string url)
{
    this->url = url;
    this->form_boundary = "sWorker" + std::to_string(time(NULL)) + "FormBoundary";
    ipfs_client = new HttpClient();
}

/**
 * @description: destructor
 */
Ipfs::~Ipfs()
{
    if (ipfs_client != NULL)
    {
        delete ipfs_client;
        ipfs_client = NULL;
    }
}

/**
 * @description: Test if there is usable IPFS
 * @return: Test result
 */
bool Ipfs::online()
{
    std::string path = this->url + "/version";
    http::response<http::string_body> res = ipfs_client->Post(path);
    if ((int)res.result() == 200)
    {
        return true;
    }

    return false;
}

/**
 * @description: Get block from ipfs
 * @param cid -> File content id
 * @param p_data_out -> Pointer to pointer to data output
 * @return: size of block, 0 for error
 */
size_t Ipfs::block_get(const char *cid, unsigned char **p_data_out)
{
    std::string path = this->url + "/block/get?arg=" + cid + "&timeout=" + block_get_timeout;
    http::response<http::string_body> res = ipfs_client->Post(path);
    int res_code = (int)res.result();
    if (res_code != 200)
    {
        switch (res_code)
        {
            case 404:
                //p_log->err("IPFS is offline! Please start it.\n");
                break;
            case 500:
                p_log->err("Get IPFS file block failed!\n");
                break;
            default:
                p_log->err("Get IPFS file block error, code: %d\n", res_code);
        }
        return 0;
    }

    std::string res_data = res.body();
    *p_data_out = (uint8_t *)malloc(res_data.size());
    memset(*p_data_out, 0, res_data.size());
    memcpy(*p_data_out, res_data.c_str(), res_data.size());

    return res_data.size();
}

/**
 * @description: Cat file
 * @param cid -> File content id
 * @param p_data_out -> Pointer to pointer to data output
 * @return: size of file, 0 for error
 */
size_t Ipfs::cat(const char *cid, unsigned char **p_data_out)
{
    std::string path = this->url + "/cat?arg=" + cid + "&timeout=" + cat_timeout;
    http::response<http::string_body> res = ipfs_client->Post(path);
    if ((int)res.result() != 200)
    {
        p_log->err("Get file error, code is: %d\n", (int)res.result());
        return 0;
    }

    std::string res_data = res.body();
    *p_data_out = (uint8_t *)malloc(res_data.size());
    memset(*p_data_out, 0, res_data.size());
    memcpy(*p_data_out, res_data.c_str(), res_data.size());

    return res_data.size();
}

/**
 * @description: Add file to ipfs
 * @param p_data_in -> Pointer to data to be added
 * @param size -> Size of added data
 * @return: Hash of the file
 */
std::string Ipfs::add(unsigned char *p_data_in, size_t size)
{
    std::string path = this->url + "/add" + "?timeout=" + add_timeout;
    std::string data(reinterpret_cast<char const *>(p_data_in), size);
    data = "\r\n--" + this->form_boundary + "\r\nContent-Disposition: form-data; name=\"\"\r\n\r\n" +
           data + "\r\n--" + this->form_boundary + "--\r\n\r\n";

    http::response<http::string_body> res = ipfs_client->Post(path, data, "multipart/form-data; boundary=" + this->form_boundary);
    if ((int)res.result() != 200)
    {
        p_log->err("Add file error, code is: %d\n", (int)res.result());
        return "";
    }

    json::JSON obj = json::JSON::Load_unsafe(res.body());

    return obj["Hash"].ToString();
}

/**
 * @description: Delete file
 * @param cid -> File content id
 * @return: Delete result
 */
bool Ipfs::del(std::string cid)
{
    std::string path = this->url + "/pin/rm?arg=" + cid;
    http::response<http::string_body> res = ipfs_client->Post(path);
    int res_code = (int)res.result();
    if (res_code != 200)
    {
        switch (res_code)
        {
            case 404:
                //p_log->err("IPFS is offline! Please start it.\n");
                break;
            case 500:
                //p_log->err("Cannot find IPFS file block!\n");
                break;
            default:
                p_log->err("Delete file error, code is: %d\n", res_code);
        }
        return false;
    }

    return true;
}
