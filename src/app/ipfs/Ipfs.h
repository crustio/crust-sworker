#ifndef _CRUST_IPFS_H_
#define _CRUST_IPFS_H_

#include "Config.h"
#include "Log.h"
#include "FormatUtils.h"

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
    size_t block_get(const char *cid, unsigned char **p_data_out);
    size_t cat(const char *cid, unsigned char **p_data_out);
    std::string add(unsigned char *p_data_in);
};

#endif /* !_CRUST_IPFS_H_ */
