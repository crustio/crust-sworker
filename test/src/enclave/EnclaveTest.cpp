#include "Enclave.h"
#include "Storage.h"
#include "Persistence.h"
#include "Identity.h"
#include "IdentityTest.h"
#include "WorkloadTest.h"
#include "SrdTest.h"
#include "ValidatorTest.h"

void ecall_handle_report_result()
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    Workload::get_instance()->handle_report_result();
}

void ecall_add_validate_proof()
{
    Workload::get_instance()->report_add_validated_srd_proof();
    Workload::get_instance()->report_add_validated_file_proof();
}

void ecall_validate_srd_test()
{
    validate_srd();
}

void ecall_validate_srd_bench()
{
    validate_srd_bench();
}

void ecall_validate_file_test()
{
    validate_meaningful_file();
}

void ecall_validate_file_bench()
{
    validate_meaningful_file_bench();
}

void ecall_store_metadata()
{
    crust_status_t crust_status = CRUST_SUCCESS;
    if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
    {
        log_err("Store enclave data failed!Error code:%lx\n", crust_status);
    }
}

void ecall_test_add_file(long file_num)
{
    WorkloadTest::get_instance()->test_add_file(file_num);
}

void ecall_test_delete_file(uint32_t file_num)
{
    WorkloadTest::get_instance()->test_delete_file(file_num);
}

void ecall_test_delete_file_unsafe(uint32_t file_num)
{
    WorkloadTest::get_instance()->test_delete_file_unsafe(file_num);
}

crust_status_t ecall_srd_increase_test(const char *uuid)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_IS_UPGRADING;
    }

    return srd_increase_test(uuid);
}

size_t ecall_srd_decrease_test(size_t change)
{
    size_t ret = srd_decrease_test(change);

    return ret;
}

void ecall_clean_file()
{
    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&wl->file_mutex);
    wl->sealed_files.clear();
    sgx_thread_mutex_unlock(&wl->file_mutex);
}

crust_status_t ecall_get_file_info(const char *data)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    crust_status_t crust_status = CRUST_UNEXPECTED_ERROR;
    for (int i = wl->sealed_files.size() - 1; i >= 0; i--)
    {
        if (wl->sealed_files[i][FILE_HASH].ToString().compare(data) == 0)
        {
            std::string file_info_str = wl->sealed_files[i].dump();
            remove_char(file_info_str, '\n');
            remove_char(file_info_str, '\\');
            remove_char(file_info_str, ' ');
            ocall_store_file_info_test(file_info_str.c_str());
            crust_status = CRUST_SUCCESS;
        }
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    return crust_status;
}

crust_status_t ecall_gen_upgrade_data_test(size_t block_height)
{
    return id_gen_upgrade_data_test(block_height);
}

crust_status_t ecall_gen_and_upload_work_report_test(const char *block_hash, size_t block_height)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }

    crust_status_t ret = gen_and_upload_work_report_test(block_hash, block_height, 0, false);

    return ret;
}

void ecall_srd_change_test(long change, bool real)
{
    if (ENC_UPGRADE_STATUS_NONE != Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    srd_change_test(change, real);
}

void ecall_validate_file_bench_real()
{
    validate_meaningful_file_bench_real();
}

void ecall_validate_srd_bench_real()
{
    validate_srd_bench_real();
}
