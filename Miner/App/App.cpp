#include "App.h"
#include "OCalls/OCalls.h"

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
    Config *config = new_config("Config.json");
    if (config == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    config->show();

    if (new_ipfs(config->ipfs_api_base_url.c_str()) == NULL)
    {
        printf("Init ipfs failed.\n");
        return false;
    }

    return true;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    /* Initialize */
    (void)(argc);
    (void)(argv);

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

    ecall_generate_root(global_eid);

    // TODO: Identity access

    /* Main loop */
    ecall_main_loop(global_eid, get_config()->empty_path.c_str());

    /* End */
    sgx_destroy_enclave(global_eid);
    delete get_config();
    delete get_ipfs();

    return 0;
}
