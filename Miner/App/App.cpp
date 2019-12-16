#include "App.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 1;

bool initialize_enclave(void);
bool initialize_components(void);
int main_daemon(void);
int main_status(void);
int main_report(const char *block_hash);

/* Application entry:
 *    use './app deamon' or './app' to start main progress
 *    use './app status' to get and printf validation status
 *    use './app report <block_hash>' to get and printf work report 
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

/* Initialize the enclave:
 *   call sgx_create_enclave to initialize an enclave instance
 */


bool initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("Init enclave failed.\n");
        return false;
    }

    return true;
}

/* Initialize the components:
 *   config -> user configurations and const configurations
 *   ipfs -> used to store meaningful files, please make sure IPFS is running before running daemon
 *   api handler -> external API interface 
 */
bool initialize_components(void)
{
    /* Config component */
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    get_config()->show();

    /* IPFS component */
    if (new_ipfs(get_config()->ipfs_api_base_url.c_str()) == NULL)
    {
        printf("Init ipfs failed.\n");
        return false;
    }

    /* API handler component */
    if (new_api_handler(get_config()->api_base_url.c_str(), &global_eid) == NULL)
    {
        printf("Init api handler failed.\n");
        return false;
    }

    return true;
}

/* Run main progress:
 *   use './app deamon' or './app' to start main progress  
 *   ps: please make sure ipfs is running before running daemon
 */
int main_daemon(void)
{
    /* Initialize dependences */
    if (!(initialize_enclave() && initialize_components()))
    {
        return -1;
    }

    /* Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores */
    #pragma omp parallel for
    for (size_t i = 0; i < get_config()->empty_capacity; i++)
    {
        ecall_plot_disk(global_eid, get_config()->empty_path.c_str());
    }

    /* TODO: Identity access */

    /* Main validate loop */
    ecall_main_loop(global_eid, get_config()->empty_path.c_str());

    /* End and release*/
    sgx_destroy_enclave(global_eid);
    delete get_config();
    delete get_ipfs();
    return 0;
}

/* Run status cmd:
 *    use './app status' to get and printf validation status 
 *    ps: please make sure daemon is running before running this cmd
 */
int main_status(void)
{
    /* Get configurations */
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(get_config()->api_base_url.c_str());
    web::uri_builder builder(U("/status"));
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    printf("%s", response.extract_utf8string().get().c_str());
    delete self_api_client;
    return 0;
}

/* Run report cmd:
 *    use './app report <block_hash>' to get and printf work report 
 *    ps: please make sure daemon is running before running this cmd
 */
int main_report(const char *block_hash)
{
    /* Get configurations */
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(get_config()->api_base_url.c_str());
    web::uri_builder builder(U("/report"));
    builder.append_query("block_hash", block_hash);
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    printf("%s", response.extract_utf8string().get().c_str());
    delete self_api_client;
    return 0;
}
