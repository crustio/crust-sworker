#ifndef _CRUST_CHAIN_H_
#define _CRUST_CHAIN_H_

#include <string>
#include "Common.h"
#include "Log.h"
#include "Config.h"
#include "HttpClient.h"

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
    Chain(std::string url, std::string password_tmp, std::string backup_tmp, bool is_offline);
    std::string url;               /* Request url */
    std::string password;          /* The password of chain account */
    std::string backup;            /* The backup of chain account */
    bool is_offline;               /* Offline mode */
    size_t offline_block_height;     /* Base offline block */
public:
    static Chain *chain;
    static Chain *get_instance();
    bool get_block_header(BlockHeader &block_header);
    std::string get_block_hash(size_t block_number);
    std::string get_swork_code();
    bool post_sworker_identity(std::string identity);
    bool post_sworker_work_report(std::string work_report);
    bool is_online(void);
    bool is_syncing(void);
    bool wait_for_running(void);
    size_t get_offline_block_height(void);
    void Chain::add_offline_block_height(size_t h);
    ~Chain();
};

} // namespace crust

#endif /* !_CRUST_CHAIN_H_ */
