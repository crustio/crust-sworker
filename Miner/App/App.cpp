#include "App.h"

bool run_as_server = false;

/**
 * @description: application entry:
 *   use './app deamon' or './app' to start main progress
 *   use './app status' to get and printf validation status
 *   use './app report <block_hash>' to get and printf work report 
 * @param argc -> the number of command parameters
 * @param argv[] -> parameter array
 * @return: exit flag
 */
int SGX_CDECL main(int argc, char *argv[])
{
    if (argc == 1 || strcmp(argv[1], "daemon") == 0)
    {
        return main_daemon();
    }
    else if (strcmp(argv[1], "status") == 0)
    {
        return main_status();
    }
    else if (strcmp(argv[1], "server") == 0)
    {
        run_as_server = true;
        return main_daemon();
    }
    else if (argc == 3 && strcmp(argv[1], "report") == 0)
    {
        return main_report(argv[2]);
    }
    else
    {
        printf("help txt\n");
    }

    return 0;
}

/**
 * @description: run main progress
 * @return: exit flag
 */
int main_daemon()
{
    return process();
}

/**
 * @description: run status command  to get and printf validation status
 * @return: exit flag
 */
int main_status()
{
    /* Get configurations */
    Config *p_config = Config::get_instance();
    if (p_config == NULL)
    {
        cfprintf(NULL, CF_ERROR "Init config failed.\n");
        return -1;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->api_base_url.c_str());
    web::uri_builder builder(U("/status"));
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    if(response.status_code() == web::http::status_codes::OK)
    {
        cfprintf(NULL, CF_INFO "%s", response.extract_utf8string().get().c_str());
    }
    else
    {
        cfprintf(NULL, CF_ERROR "Get status failed!\n");
    }
    delete self_api_client;
    delete p_config;
    return 0;
}

/**
 * @description: run report command to get and printf work report
 * @param block_hash -> use this hash to create report
 * @return: exit flag
 */
int main_report(const char *block_hash)
{
    /* Get configurations */
    Config *p_config = Config::get_instance();
    if (p_config == NULL)
    {
        cfprintf(NULL, CF_ERROR "Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->api_base_url.c_str());
    web::uri_builder builder(U("/report"));
    builder.append_query("block_hash", block_hash);
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    cfprintf(NULL, CF_INFO "%s", response.extract_utf8string().get().c_str());
    delete self_api_client;
    delete p_config;
    return 0;
}
