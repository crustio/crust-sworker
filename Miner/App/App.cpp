#include "App.h"
#include "OCalls/OCalls.h"
#include <pthread.h>

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

    size_t size = 15;
    ecall_plot_disk(global_eid, "", &size);
    ecall_plot_disk(global_eid, "", &size);

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
