#include "App.h"
#include "OCalls/OCalls.h"

sgx_enclave_id_t global_eid = 1;

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
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
    
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    return 0;
}

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Init enclave failed\n");
        return -1;
    }

    return 0;
}
