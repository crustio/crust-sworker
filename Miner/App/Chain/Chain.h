#ifndef _CRUST_CHAIN_H_
#define _CRUST_CHAIN_H_

#include <string>
#include "Common.h"
#include "HttpLib.h"
#include "Json.hpp"
#include "Log.h"

struct BlockHeader
{
    size_t number;    /* Current block number */
    std::string hash; /* Current block hash */
};

class Chain
{
private:
    UrlEndPoint *url_end_point;    /* Url end point info */
    httplib::Client *chain_client; /* Used to call crust chian API */
    std::string password;          /* The password of chain account */
    std::string backup;            /* The backup of chain account */
public:
    BlockHeader *get_block_header(void);
    bool post_tee_identity(std::string identity);
    bool post_tee_work_report(std::string work_report);
    Chain(std::string url, std::string password_tmp, std::string backup_tmp);
    bool is_online(void);
    ~Chain();
};

Chain *new_chain(std::string url, std::string password, std::string backup);
Chain *get_chain(void);

#endif /* !_CRUST_CHAIN_H_ */
