#include "App.h"
#include "OCalls/OCalls.h"

sgx_enclave_id_t global_eid = 1;

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        return -1;
    }

    // TODO: config part
    size_t num_g = 4;
    std::string dir_path = "store";

#pragma omp parallel for
    for (size_t i = 0; i < num_g; i++)
    {
        ecall_plot_disk(global_eid, dir_path.c_str());
    }

    ecall_generate_root(global_eid);

    while (true)
    {
        ecall_validate_empty_disk(global_eid, dir_path.c_str());
        break;
    }

    Ipfs *ipfs = get_ipfs("http://127.0.0.1:5001/api/v0");

    for (size_t i = 0; i < 10; i++)
    {
        Node *files = ipfs->get_files();
        ecall_validate_meaningful_disk(global_eid, files, ipfs->get_files_num(), ipfs->get_files_space_size());
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    delete ipfs;

    return 0;
}

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("Init enclave failed\n");
        return -1;
    }

    return 0;
}
