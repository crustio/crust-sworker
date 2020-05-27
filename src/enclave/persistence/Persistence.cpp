#include "Persistence.h"
#include "EUtils.h"
#include "sgx_tseal.h"

using namespace std;

/**
 * @description: Add value by key
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Add status
 * */
crust_status_t persist_add(const char *key, const uint8_t *value, size_t value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    crust_status = seal_data_mrenclave(value, value_len, &p_sealed_data, &sealed_data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    uint8_t *p_sealed_data_r = (uint8_t*)malloc(sealed_data_size);
    memset(p_sealed_data_r, 0, sealed_data_size);
    memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
    free(p_sealed_data);

    ocall_persist_add(&crust_status, key, p_sealed_data_r, sealed_data_size);
    free(p_sealed_data_r);

    return crust_status;
}

/**
 * @description: Delete value by key
 * @param key -> Pointer to key
 * @return: Delete status
 * */
crust_status_t persist_del(const char *key)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_persist_del(&crust_status, key);

    return crust_status;
}

/**
 * @description: Update value by key
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Update status
 * */
crust_status_t persist_set(const char *key, const uint8_t *value, size_t value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    crust_status = seal_data_mrenclave(value, value_len, &p_sealed_data, &sealed_data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    uint8_t *p_sealed_data_r = (uint8_t*)malloc(sealed_data_size);
    memset(p_sealed_data_r, 0, sealed_data_size);
    memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
    free(p_sealed_data);

    ocall_persist_set(&crust_status, key, p_sealed_data_r, sealed_data_size);
    free(p_sealed_data_r);

    return crust_status;
}

/**
 * @description: Get value by key
 * @param key -> Pointer to key
 * @param value -> Pointer points to value
 * @param value_len -> Pointer to value length
 * @return: Get status
 * */
crust_status_t persist_get(const char *key, uint8_t **value, size_t *value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    // Get sealed data
    uint8_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    ocall_persist_get(&crust_status, key, &p_sealed_data, &sealed_data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // Get unsealed data
    sgx_sealed_data_t *p_sealed_data_r = (sgx_sealed_data_t*)malloc(sealed_data_size);
    memset(p_sealed_data_r, 0, sealed_data_size);
    memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
    uint32_t unsealed_data_size = sgx_get_encrypt_txt_len(p_sealed_data_r);
    uint8_t *p_unsealed_data = (uint8_t*)enc_malloc(unsealed_data_size);
    memset(p_unsealed_data, 0, unsealed_data_size);
    sgx_status = sgx_unseal_data(p_sealed_data_r, NULL, NULL,
            p_unsealed_data, &unsealed_data_size);
    if (SGX_SUCCESS != sgx_status)
    {
        log_err("Unseal data failed!Error code:%lx\n", sgx_status);
        crust_status = CRUST_UNSEAL_DATA_FAILED;
        free(p_unsealed_data);
        goto cleanup;
    }

    *value = p_unsealed_data;
    *value_len = unsealed_data_size;

cleanup:
    free(p_sealed_data_r);

    return crust_status;
}
