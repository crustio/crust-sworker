#include "ApiHandler.h"

ApiHandler *api_handler = NULL;

ApiHandler *new_api_handler(const char *url, sgx_enclave_id_t *p_global_eid)
{
    if (api_handler != NULL)
    {
        delete api_handler;
    }

    utility::string_t address = U(url);
    web::uri_builder uri(address);
    api_handler = new ApiHandler(uri.to_uri().to_string(), p_global_eid);
    return api_handler;
}

ApiHandler *get_api_handler()
{
    if (api_handler == NULL)
    {
        printf("Please use new_api_handler(url, &global_eid) frist.\n");
        exit(-1);
    }

    return api_handler;
}

ApiHandler::ApiHandler(utility::string_t url, sgx_enclave_id_t *p_global_eid_in) : m_listener(url)
{
    this->p_global_eid = p_global_eid_in;
    this->m_listener.support(web::http::methods::GET, std::bind(&ApiHandler::handle_get, this, std::placeholders::_1));
    this->m_listener.open().wait();
}

void ApiHandler::handle_get(web::http::http_request message)
{
    message.reply(web::http::status_codes::OK, "ACCEPTED");
};
