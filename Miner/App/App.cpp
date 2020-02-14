#include "App.h"

bool run_as_server = false;
extern std::string config_file_path;

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
    // Get configure file path if exists
    std::string run_type;
    for(int i=1;i<argc;i++)
    {
        if(strcmp(argv[i], "-c") == 0)
        {
            if(i+1 < argc)
            {
                config_file_path = std::string(argv[i+1]);
                i++;
            }
            else
            {
                cfprintf(NULL, CF_ERROR "-c option needs configure file path as argument!\n");
                return 1;
            }
        }
        else
        {
            if(run_type.compare("") != 0)
            {
                cfprintf(NULL, CF_ERROR "Ambiguos run mode!\n");
                return 1;
            }
            run_type = argv[i];
        }
    }

    // Main branch
    if(run_type.compare("status") == 0)
    {
        return main_status();
    }
    else if(run_type.compare("report") == 0)
    {
        return main_report();
    }
    else if(run_type.compare("daemon") == 0 || run_type.compare("") == 0)
    {
        return main_daemon();
    }
    else if(run_type.compare("server") == 0)
    {
        run_as_server = true;
        return main_daemon();
    }
    else
    {
        printf("    Usage: \n");
        printf("        %s <option> <argument>\n", argv[0]);
        printf("          option: \n");
        printf("           -h: help information. \n");
        printf("           -c: indicate configure file path, followed by configure file path. \n");
        printf("               If no file provided, default path is <crust_dir>/etc/Config.json. \n");
        printf("           status: show plot disk status. \n");
        printf("           report: show plot work report. \n");
        printf("           daemon: run as daemon process. \n");
        printf("           server: run as server node. \n");
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
        cfprintf(NULL, CF_INFO "Get status failed!");
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
