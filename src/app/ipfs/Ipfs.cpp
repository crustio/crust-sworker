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
