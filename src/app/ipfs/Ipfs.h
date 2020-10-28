#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include "Config.h"
#include "Log.h"

class Ipfs
{
private:
    static Ipfs *ipfs;
    Ipfs(std::string url);
    ~Ipfs();
    std::string url;
public:
    static Ipfs *get_instance();
    bool online();
};

#endif /* !_CRUST_IPFS_H_ */
