#include "App.h"

bool offline_chain_mode = false;
extern std::string config_file_path;
crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: application main entry
 * @param argc -> the number of command parameters
 * @param argv[] -> parameter array
 * @return: exit flag
 */
int SGX_CDECL main(int argc, char *argv[])
{
    // Get configure file path if exists
    bool is_set_config = false;
    std::string run_type;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            goto show_help;
        }
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0)
        {
            if (i + 1 < argc)
            {
                config_file_path = std::string(argv[i + 1]);
                i++;
                is_set_config = true;
            }
            else
            {
                p_log->err("-c option needs configure file path as argument!\n");
                goto show_help;
            }
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            printf("Release version: %s\
                  \nTEE     version: %s\n", VERSION, TEE_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--offline") == 0)
        {
            offline_chain_mode = true;
        }
        else if (strcmp(argv[i], "--debug") == 0)
        {
            p_log->open_debug();
            p_log->debug("Debug log is opened.\n");
        }
        else if (strcmp(argv[i], "--update") == 0)
        {
            if (i + 1 < argc)
            {
                // Get srd reserved space
                long srd_reserved_space = 0;
                if (!is_number(argv[i+1]))
                {
                    // If old TEE url is provided, get srd reserved space from it
                    srd_reserved_space = get_old_reserved_space(argv[i+1]) - 10;
                }
                else
                {
                    srd_reserved_space = atoi(argv[i+1]);
                }
                // Check if srd reserved is valid
                if (srd_reserved_space == -1)
                {
                    p_log->err("Get old srd reserved space failed!\n");
                    return 1;
                }
                else if (srd_reserved_space < 10)
                {
                    p_log->err("Old srd reserved:%ld is less than 10!\n", srd_reserved_space);
                    return 1;
                }
                set_reserved_space(srd_reserved_space);
                p_log->info("Update is performed!Srd reserved space has been set to %ld.\
                        Make sure you have set srd space in your config file!\n", srd_reserved_space);
                i++;
            }
            else
            {
                p_log->err("--update option needs srd space as argument!\n");
                goto show_help;
            }
        }
        else
        {
            if (run_type.compare("") != 0)
            {
                p_log->err("Ambiguos run mode!\n");
                return 1;
            }
            run_type = argv[i];
        }
    }

    // Check if configure path has been indicated
    if (!is_set_config)
    {
        p_log->err("Please indicate configure file path!\n");
        goto show_help;
    }

    // Main branch
    if (run_type.compare("status") == 0)
    {
        return main_status();
    }
    else if (run_type.compare("report") == 0)
    {
        return main_report();
    }
    else if (run_type.compare("daemon") == 0 || run_type.compare("") == 0)
    {
        return main_daemon();
    }


show_help:

    printf("    Usage: \n");
    printf("        %s <option> <argument>\n", argv[0]);
    printf("          option: \n");
    printf("           -h, --help: help information. \n");
    printf("           -c, --config: indicate configure file path, followed by configure file path. Like: '--config Config.json'\n");
    printf("               If no file provided, default path is etc/Config.json. \n");
    printf("           --offline: add this flag, program will not interact with the chain. \n");
    printf("           --debug: add this flag, program will output debug logs. \n");
    printf("           --update: used to update, parameter can be:\n");
    printf("               1.Srd space(should not exceed old TEE), like 40,\n");
    printf("               2.Old TEE url, like 'http://localhost:12222/api/v0', it can be used to get old TEE srd_reserved_space.\n");
    printf("                 And new TEE's srd_reserved_space will be set to (old_srd_reserved_space - 10).\n");
    printf("           status: show validate status. \n");
    printf("           report: show work report. \n");
    printf("           daemon: run as daemon process(this mode is the default one). \n");

    return 0;
}

/**
 * @description: run main progress
 * @return: exit flag
 */
int main_daemon()
{
    return process_run();
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
        p_log->err("Init config failed.\n");
        return -1;
    }

    /* Call internal api interface to get information */
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);
    httplib::Client *client = new httplib::Client(urlendpoint->ip, urlendpoint->port);
    std::string path = urlendpoint->base + "/status";
    auto res = client->Get(path.c_str());
    if (!(res && res->status == 200))
    {
        p_log->info("Get status failed!");
        return -1;
    }
    p_log->err("%s", res->body.c_str());

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
        p_log->err("Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);
    httplib::Client *client = new httplib::Client(urlendpoint->ip, urlendpoint->port);
    std::string path = urlendpoint->base + "/report";
    auto res = client->Get(path.c_str());
    if (!(res && res->status == 200))
    {
        p_log->info("Get report failed!");
        return -1;
    }
    p_log->info("%s", res->body.c_str());

    delete p_config;
    delete client;
    return 0;
}
