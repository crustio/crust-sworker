#ifndef _APP_ENCLAVE_DATA_TEST_H_
#define _APP_ENCLAVE_DATA_TEST_H_

#include <stdio.h>
#include <string>

#include "EnclaveData.h"

class EnclaveDataTest
{
public:
    static EnclaveDataTest *enclavedataTest;
    static EnclaveDataTest *get_instance();

    void set_file_info(std::string file_info);
    std::string get_file_info();
    std::string g_file_info = "";
    std::string enclave_workreport = "";

private:
    EnclaveDataTest() {}
};

#endif /* !_APP_ENCLAVE_DATA_TEST_H_ */
