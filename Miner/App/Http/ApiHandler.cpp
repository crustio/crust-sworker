#include "ApiHandler.h"

ApiHandler *api_handler = NULL;
/* Used to show validation status*/
const char *validation_status_strings[] = {"ValidateStop", "ValidateWaiting", "ValidateMeaningful", "ValidateEmpty"};

/**
 * @description: new a global API handler
 * @param url API base url 
 * @param p_global_eid The point for sgx global eid 
 * @return: the point of API handler
 */
ApiHandler *new_api_handler(const char *url, sgx_enclave_id_t *p_global_eid)
{
    if (api_handler != NULL)
    {
        delete api_handler;
    }

    api_handler = new ApiHandler(url, p_global_eid);
    return api_handler;
}

/**
 * @description: get the global API handler
 * @return: the point of API handler
 */
ApiHandler *get_api_handler(void)
{
    if (api_handler == NULL)
    {
        printf("Please use new_api_handler(url, &global_eid) frist.\n");
        exit(-1);
    }

    return api_handler;
}

/**
 * @description: constructor
 * @param url API base url 
 * @param p_global_eid The point for sgx global eid  
 */
ApiHandler::ApiHandler(utility::string_t url, sgx_enclave_id_t *p_global_eid_in) : m_listener(url)
{
    this->p_global_eid = p_global_eid_in;
    this->m_listener.support(web::http::methods::GET, std::bind(&ApiHandler::handle_get, this, std::placeholders::_1));
    this->m_listener.open().wait();
}

/**
 * @description: destructor
 */
ApiHandler::~ApiHandler()
{
    this->m_listener.close().wait();
    delete this->p_global_eid;
}

/**
 * @description: handle get requests
 * @param message http request message
 */
void ApiHandler::handle_get(web::http::http_request message)
{
    /* Handle status request */
    if (message.relative_uri().path() == "/status")
    {
        enum ValidationStatus validation_status = ValidateStop;

        if (ecall_return_validation_status(*this->p_global_eid, &validation_status) != SGX_SUCCESS)
        {
            printf("Get validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        message.reply(web::http::status_codes::OK, std::string("{'validationStatus':") + validation_status_strings[validation_status] + "}");
        return;
    }

    /* Handle report request */
    if (message.relative_uri().path() == "/report")
    {
        /* Get block hash from url */
        auto arg_map = web::http::uri::split_query(message.request_uri().query());

        if (arg_map.find("block_hash") == arg_map.end())
        {
            message.reply(web::http::status_codes::BadRequest, "BadRequest");
            return;
        }

        /* Call ecall function to get work report */
        size_t report_len = 0;
        if (ecall_generate_validation_report(*this->p_global_eid, &report_len, arg_map["block_hash"].c_str()) != SGX_SUCCESS)
        {
            printf("Generate validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        char *report = new char[report_len];
        if (ecall_get_validation_report(*this->p_global_eid, report, report_len) != SGX_SUCCESS)
        {
            printf("Get validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        if (report == NULL)
        {
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        message.reply(web::http::status_codes::OK, report);
        return;
    }

    message.reply(web::http::status_codes::BadRequest, "BadRequest");
    return;
};
