#include "App.h"

sgx_enclave_id_t global_eid = 1;

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

bool initialize_component(void)
{
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    get_config()->show();

    if (new_ipfs(get_config()->ipfs_api_base_url.c_str()) == NULL)
    {
        printf("Init ipfs failed.\n");
        return false;
    }

    if(new_api_handler(get_config()->api_base_url.c_str(), &global_eid) == NULL)
    {
        printf("Init api handler failed.\n");
        return false;
    }
    
    return true;
}

int main_daemon()
{
    if (!(initialize_enclave() && initialize_component()))
    {
        return -1;
    }

    /* Plot empty disk */
    #pragma omp parallel for
    for (size_t i = 0; i < get_config()->empty_capacity; i++)
    {
        ecall_plot_disk(global_eid, get_config()->empty_path.c_str());
    }

    ecall_generate_empty_root(global_eid);

    // TODO: Identity access

    /* Main loop */
    ecall_main_loop(global_eid, get_config()->empty_path.c_str());

    /* End */
    sgx_destroy_enclave(global_eid);
    delete get_config();
    delete get_ipfs();
    return 0;
}

int main_status()
{
    return 0;
}

int main_report(const char *block_hash)
{
    return 0;
}

/* Application entry */
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
