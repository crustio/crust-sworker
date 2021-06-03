#include "ECallsTest.h"

EnclaveQueue *eq = EnclaveQueue::get_instance();

sgx_status_t Ecall_handle_report_result(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_handle_report_result(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_add_validate_proof(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_add_validate_proof(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_srd_test(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_srd_test(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_srd_bench(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_srd_bench(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_file_test(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file_test(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_file_bench(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file_bench(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_store_metadata(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_store_metadata(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_add_file(sgx_enclave_id_t eid, long file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_add_file(eid, file_num);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_delete_file(sgx_enclave_id_t eid, uint32_t file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_delete_file(eid, file_num);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_delete_file_unsafe(sgx_enclave_id_t eid, uint32_t file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_delete_file_unsafe(eid, file_num);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_srd_increase_test(sgx_enclave_id_t eid, crust_status_t *status, const char *uuid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_increase_test(eid, status, uuid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_srd_decrease_test(sgx_enclave_id_t eid, size_t *size, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_decrease_test(eid, size, change);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_clean_file(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_clean_file(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_get_file_info(sgx_enclave_id_t eid, crust_status_t *status, const char *data)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_file_info(eid, status, data);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_gen_upgrade_data_test(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_upgrade_data_test(eid, status, block_height);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_gen_and_upload_work_report_test(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_gen_and_upload_work_report_test(eid, status, block_hash, block_height);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_srd_change_test(sgx_enclave_id_t eid, long change, bool real)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_change_test(eid, change, real);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_file_bench_real(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file_bench_real(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_srd_bench_real(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_srd_bench_real(eid);

    eq->free_enclave(__FUNCTION__);

    return ret;
}
