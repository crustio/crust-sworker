#ifndef _CRUST_CHAIN_H_
#define _CRUST_CHAIN_H_

#include <string>
#include "Common.h"
#include "Json.hpp"
#include "Log.h"
#include "Config.h"

namespace crust
{

struct BlockHeader
{
    size_t number;    /* Current block number */
    std::string hash; /* Current block hash */
};

class Chain
{
private:
    Chain(std::string url, std::string password_tmp, std::string backup_tmp);
    UrlEndPoint *url_end_point;    /* Url end point info */
    std::string url;               /* Request url */
    std::string password;          /* The password of chain account */
    std::string backup;            /* The backup of chain account */
public:
    static Chain *chain;
    static Chain *get_instance();
    BlockHeader *get_block_header(void);
    std::string get_block_hash(size_t block_number);
    bool post_tee_identity(std::string identity);
    bool post_tee_work_report(std::string work_report);
    bool is_online(void);
    bool wait_for_running(void);
    ~Chain();
};

} // namespace crust

#endif /* !_CRUST_CHAIN_H_ */
