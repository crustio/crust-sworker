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
public:
    BlockHeader *GetBlockHeader();
    Crust(const char *url);
    bool is_online(void);
    ~Crust();
};

Crust *new_crust(const char *url);
Crust *get_crust(void);

#endif /* !_CRUST_CRSUT_H_ */
