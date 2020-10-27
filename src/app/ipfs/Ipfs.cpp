#include "Ipfs.h"

crust::Log *p_log = crust::Log::get_instance();

Ipfs *Ipfs::ipfs = NULL;

/**
 * @desination: single instance class function to get instance
 * @return: ipfs instance
 */
Ipfs *ipfs::get_instance()
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
    this->ipfs_client = new HttpClient();
}

/**
 * @description: destructor
 */
Ipfs::~Ipfs()
{
    if (this->ipfs_client != NULL)
    {
        delete this->ipfs_client;
        this->ipfs_client = NULL;
    }
}
