#include "OCallsTest.h"

crust::Log *p_log = crust::Log::get_instance();

crust_status_t ocall_srd_change_test(long change)
{
    return srd_change_test(change) ? CRUST_SUCCESS : CRUST_UNEXPECTED_ERROR;
}

crust_status_t ocall_get_file_bench(const char * /*file_path*/, unsigned char **p_file, size_t *len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (access("<%CRUST_TEST_SRD_PATH%>", 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat ("<%CRUST_TEST_SRD_PATH%>", &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open("<%CRUST_TEST_SRD_PATH%>", std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    uint8_t *p_data = (uint8_t *)malloc(*len);
    memset(p_data, 0, *len);

    in.read(reinterpret_cast<char *>(p_data), *len);
    in.close();

    *p_file = p_data;

    return crust_status;
}

void ocall_store_file_info_test(const char *info)
{
    EnclaveDataTest::get_instance()->set_file_info(info);
}

crust_status_t ocall_get_file_block(const char *file_path, unsigned char **p_file, size_t *len)
{
    std::string file_path_r = std::string("<%CRUST_FILE_PATH%>").append(file_path);
    if (access(file_path_r.c_str(), 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat (file_path_r.c_str(), &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(file_path_r, std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    uint8_t *p_data = (uint8_t *)malloc(*len);
    memset(p_data, 0, *len);

    in.read(reinterpret_cast<char *>(p_data), *len);
    in.close();

    *p_file = p_data;

    return CRUST_SUCCESS;
}

crust_status_t ocall_upload_workreport_test(const char *work_report)
{
    std::string work_str(work_report);
    remove_char(work_str, '\\');
    remove_char(work_str, '\n');
    remove_char(work_str, ' ');
    p_log->info("Sending work report:%s\n", work_str.c_str());
    EnclaveDataTest::get_instance()->set_enclave_workreport(work_str);

    p_log->info("Send work report to crust chain successfully!\n");

    return CRUST_SUCCESS;
}

void ocall_recall_validate_file_bench()
{
    validate_file_test();
}

void ocall_recall_validate_srd_bench()
{
    validate_srd_test();
}
