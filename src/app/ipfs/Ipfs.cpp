#include "Ipfs.h"
#include "HttpClient.h"

crust::Log *p_log = crust::Log::get_instance();
HttpClient *ipfs_client = NULL;
Ipfs *Ipfs::ipfs = NULL;

/**
 * @desination: single instance class function to get instance
 * @return: ipfs instance
 */
Ipfs *Ipfs::get_instance()
{
    if (Ipfs::ipfs == NULL)
    {
        Config *p_config = Config::get_instance();
        Ipfs::ipfs = new Ipfs("http://127.0.0.1:5001/api/v0");
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
    this->form_boundary = std::to_string(time(NULL)) + "yasimola";
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
 * */
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
 * @return: size of block, 0 for error	
 * */
size_t Ipfs::block_get(const char *cid, unsigned char **p_data_out)
{
    std::string path = this->url + "/block/get?arg=" + cid;
    http::response<http::string_body> res = ipfs_client->Post(path);
    if ((int)res.result() != 200)
    {
        p_log->err("Get block from ipfs error, code is: %d\n", (int)res.result());
        return 0;
    }

    *p_data_out = new unsigned char[res.body().size()];
    std::copy(res.body().begin(), res.body().end(), *p_data_out);

    return res.body().size();
}

size_t Ipfs::cat(const char *cid, unsigned char **p_data_out)
{
    std::string path = this->url + "/cat?arg=" + cid;
    http::response<http::string_body> res = ipfs_client->Post(path);
    if ((int)res.result() != 200)
    {
        p_log->err("Get file error, code is: %d\n", (int)res.result());
        return 0;
    }

    *p_data_out = new unsigned char[res.body().size()];
    std::copy(res.body().begin(), res.body().end(), *p_data_out);

    return res.body().size();
}

std::string Ipfs::add(unsigned char *p_data_in, size_t size)
{
    std::string path = this->url + "/add";
    std::string data(reinterpret_cast<char const *>(p_data_in), size);
    data = "\r\n--" + this->form_boundary + "\r\nContent-Disposition: form-data; name=\"\"\r\n\r\n" +
           data + "\r\n--" + this->form_boundary + "--\r\n\r\n";
    std::string content_type = "multipart/form-data; boundary=" + this->form_boundary;
    
    http::response<http::string_body> res = ipfs_client->Post(path, data, content_type);
    if ((int)res.result() != 200)
    {
        p_log->err("Add file error, code is: %d\n", (int)res.result());
        return "";
    }

    json::JSON obj = json::JSON::Load(res.body());

    return obj["Hash"].ToString();
}
