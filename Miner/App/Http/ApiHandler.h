#ifndef _CRUST_API_HANDLER_H_
#define _CRUST_API_HANDLER_H_

#include <stdio.h>
#include <algorithm>
#include <mutex>
#include <sgx_report.h>
#include <sgx_key_exchange.h>
#include <sgx_error.h>
#include "Enclave_u.h"
#include "sgx_eid.h"
#include "Common.h"
#include "Config.h"
#include "Logfile.h"
#include "FormatUtils.h"
#include "IASReport.h"
#include "SgxSupport.h"
#include "Resource.h"
#include "HttpLib.h"


class ApiHandler
{
public:
    ApiHandler(sgx_enclave_id_t *p_global_eid_in);
    ~ApiHandler();
    int start();
    int stop();
    int test = 32;

private:
    sgx_enclave_id_t *p_global_eid;                                     /* The point for sgx global eid*/
    httplib::Server *server;
    void handle_get(httplib::Request req);
    void handle_post(httplib::Request req);
};

#endif /* !_CRUST_API_HANDLER_H_ */
