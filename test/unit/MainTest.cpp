#include "MainTest.h"

int main()
{
    int ret = test_enclave();
    return ret;
}

int test_enclave()
{
    std::string HRED = "\033[1;31m";
    std::string HGREEN = "\033[1;32m";
    std::string NC = "\033[0m";
    bool test_ret = true;
    printf("\nRunning enclave test...\n\n");

    /* Launch the enclave */
    sgx_enclave_id_t eid;
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_TEST_FILE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("%s*** Create enclave failed!%s\n", HRED.c_str(), NC.c_str());
        return -1;
    }

    /* Running enclave utils tests */
    ret = ecall_test_enclave_unit(eid, &test_ret);
    printf("\n");
    if (SGX_SUCCESS != ret)
    {
        printf("%s*** Invoke SGX failed!%s\n", HRED.c_str(), NC.c_str());
        return -1;
    }
    if (!test_ret)
    {
        printf("%s*** Test enclave utils APIs failed!%s\n", HRED.c_str(), NC.c_str());
        return -1;
    }

    printf("%s*** Pass enclave test!%s\n", HGREEN.c_str(), NC.c_str());

    return test_ret ? 0 : -1;
}

