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
    else if (strcmp(argv[1], "report") == 0)
    {
        return main_report();
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
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);
    httplib::Client *client = new httplib::Client(urlendpoint->ip, urlendpoint->port);
    std::string path = urlendpoint->base + "/status";
    auto res = client->Get(path.c_str());
    if(!(res && res->status == 200))
    {
        cfprintf(NULL, CF_INFO "Get report failed!");
        return -1;
    }
    cfprintf(NULL, CF_INFO "%s", res->body.c_str());

    delete p_config;
    delete client;
    return 0;
}

/**
 * @description: run report command to get and printf work report
 * @return: exit flag
 */
int main_report()
{
    /* Get configurations */
    Config *p_config = Config::get_instance();
    if (p_config == NULL)
    {
        cfprintf(NULL, CF_ERROR "Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);
    httplib::Client *client = new httplib::Client(urlendpoint->ip, urlendpoint->port);
    std::string path = urlendpoint->base + "/report";
    auto res = client->Get(path.c_str());
    if(!(res && res->status == 200))
    {
        cfprintf(NULL, CF_INFO "Get report failed!");
        return -1;
    }
    cfprintf(NULL, CF_INFO "%s", res->body.c_str());


    delete p_config;
    delete client;
    return 0;
}
