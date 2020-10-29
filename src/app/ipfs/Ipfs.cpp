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
    http::response<http::string_body> res = ipfs_client->Post(path.c_str());
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
    http::response<http::string_body> res = ipfs_client->Post(path.c_str());
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
    http::response<http::string_body> res = ipfs_client->Post(path.c_str());
    if ((int)res.result() != 200)
    {
        p_log->err("Get file error, code is: %d\n", (int)res.result());
        return 0;
    }

    *p_data_out = new unsigned char[res.body().size()];
    std::copy(res.body().begin(), res.body().end(), *p_data_out);

    return res.body().size();
}

std::string Ipfs::add(unsigned char *p_data_in)
{
    std::string path = this->url + "/add";
    std::string data(reinterpret_cast<char const *>(p_data_in));
    ApiHeaders headers = {{"data", data}, {"Content-Type", "multipart/form-data"}};

    http::response<http::string_body> res = ipfs_client->Post(path.c_str(), "", headers);
    if ((int)res.result() != 200)
    {
        p_log->err("Add file error, code is: %d\n", (int)res.result());
        return 0;
    }

    return res.body();
}
