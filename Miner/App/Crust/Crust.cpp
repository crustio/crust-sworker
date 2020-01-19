#include "Crust.h"

Crust *crust = NULL;

extern FILE *felog;

/**
 * @description: new a global crust handler to access crust node
 * @param url -> crust API base url
 * @param password -> the password of chain account id
 * @param backup ->  the backup of chain account id
 * @return: the point of crust handler
 */
Crust *new_crust(std::string url, std::string password, std::string backup)
{
    if (crust != NULL)
    {
        delete crust;
    }

    crust = new Crust(url, password, backup);
    return crust;
}

/**
 * @description: get the global crust handler to access crust node 
 * @return: the point of crust handle
 */
Crust *get_crust(void)
{
    if (crust == NULL)
    {
        cfprintf(felog, CF_ERROR "Please use new_crust(url) frist.\n");
    }

    return crust;
}

/**
 * @description: new a crust handler to access crust node
 * @param url -> crust API base url, like: http://127.0.0.1:56666/api/v1
 * @param password -> the password of chain account id
 * @param backup ->  the backup of chain account id
 */
Crust::Crust(std::string url, std::string password, std::string backup)
{
    this->crust_client = new web::http::client::http_client(url);
    this->password = password;
    this->backup = backup;
}

/**
 * @description: destructor
 */
Crust::~Crust()
{
    delete this->crust_client;
}

/**
 * @description: get laster block header from Crust
 * @return: the point of block header
 */
BlockHeader *Crust::get_block_header(void)
{
    web::uri_builder builder(U("/block/header"));
    web::http::http_response response = this->crust_client->request(web::http::methods::GET, builder.to_string()).get();

    if (response.status_code() != web::http::status_codes::OK)
    {
        return NULL;
    }

    web::json::value block_header_json = response.extract_json().get();
    BlockHeader *block_header = new BlockHeader();
    block_header->hash = block_header_json["hash"].as_string();
    block_header->number = block_header_json["number"].as_integer();

    return block_header;
}

/**
 * @description: test if there is usable crust api
 * @return: test result
 * */
bool Crust::is_online(void)
{
    try
    {
        web::uri_builder builder(U("/block/header"));
        web::http::http_response response = this->crust_client->request(web::http::methods::GET, builder.to_string()).get();
        if (response.status_code() != web::http::status_codes::OK)
        {
            return false;
        }

        return true;
    }
    catch (const web::http::http_exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
    }
    catch (const std::exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
    }

    return false;
}

/**
 * @description: post tee identity to crust chain
 * @param identity -> tee identity
 * @return: success or fail
 * */
bool Crust::post_tee_identity(std::string identity)
{
    try
    {
        web::http::http_request req(web::http::methods::POST);
        req.headers().add(U("password"), U(this->password));
        req.headers().add(U("Content-Type"), U("application/json"));
        req.set_request_uri(U("/tee/identity"));
        std::string body = "{\"identity\":\"" + identity + "\",\"backup\":\"" + this->backup + "\"}";
        req.set_body(body);

        web::http::http_response response = this->crust_client->request(req).get();
        if (response.status_code() != web::http::status_codes::OK)
        {
            return false;
        }
    }
    catch (const web::http::http_exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
    }
    catch (const std::exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
    }

    return true;
}

/**
 * @description: post tee work report to crust chain
 * @param work_report -> tee work report
 * @return: success or fail
 * */
bool Crust::post_tee_work_report(std::string work_report)
{
    try
    {
        web::http::http_request req(web::http::methods::POST);
        req.headers().add(U("password"), U(this->password));
        req.headers().add(U("Content-Type"), U("application/json"));
        req.set_request_uri(U("/tee/workreport"));
        std::string body = "{\"workreport\":\"" + work_report + "\",\"backup\":\"" + this->backup + "\"}";
        req.set_body(body);

        web::http::http_response response = this->crust_client->request(req).get();
        if (response.status_code() != web::http::status_codes::OK)
        {
            return false;
        }
    }
    catch (const web::http::http_exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
    }
    catch (const std::exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
    }

    return true;
}
