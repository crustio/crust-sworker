#ifndef _CRUST_CRSUT_H_
#define _CRUST_CRSUT_H_

#include <string>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include "Common.h"

struct BlockHeader
{
    size_t number;    /* Current block number */
    std::string hash; /* Current block hash */
};

class Crust
{
private:
    web::http::client::http_client *crust_client; /* Used to call Crust API */
    std::string password;                         /* The password of chain account id */
    std::string backup;                           /* The backup of chain account id */
public:
    BlockHeader *get_block_header(void);
    bool post_tee_identity(std::string identity);
    bool post_tee_work_report(std::string work_report);
    Crust(std::string url, std::string password, std::string backup);
    bool is_online(void);
    ~Crust();
};

Crust *new_crust(std::string url, std::string password, std::string backup);
Crust *get_crust(void);

#endif /* !_CRUST_CRSUT_H_ */
