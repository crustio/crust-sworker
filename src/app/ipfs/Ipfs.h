#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include "Config.h"
#include "Log.h"
#include "HttpClient.h"

class Ipfs
{
private:
    static Ipfs *ipfs;
    Ipfs(std::string url);
    HttpClient *ipfs_client;
    std::string url;
public:
    static Ipfs *get_instance();
};

#endif /* !_CRUST_IPFS_H_ */
