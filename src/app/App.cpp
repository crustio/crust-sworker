#include "App.h"

bool offline_chain_mode = false;
bool g_init_upgrade = false;
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
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            goto show_help;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                p_log->err("-c option needs configure file path as argument!\n");
                return 1;
            }
            config_file_path = std::string(argv[i + 1]);
            is_set_config = true;
            i++;
        }
        else if (strcmp(argv[i], "--upgrade") == 0)
        {
            g_init_upgrade = true;
            i++;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0)
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
            p_log->set_debug(true);
            p_log->debug("Debug log is opened.\n");
        }
        else
        {
            goto show_help;
        }
    }

    // Check if configure path has been indicated
    if (!is_set_config)
    {
        p_log->err("Please indicate configure file path!\n");
        goto show_help;
    }

    // Main branch
    return main_daemon();


show_help:

    printf("    Usage: \n");
    printf("        %s <option> <argument>\n", argv[0]);
    printf("          option: \n");
    printf("           -h, --help: help information. \n");
    printf("           -c, --config: required, indicate configure file path, followed by configure file path. Like: '--config Config.json'\n");
    printf("               If no file provided, default path is etc/Config.json. \n");
    printf("           -v, --version: show whole version and sworker version. \n");
    printf("           --offline: add this flag, program will not interact with the chain. \n");
    printf("           --debug: add this flag, program will output debug logs. \n");
    printf("           --upgrade: used to upgrade.\n");

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
