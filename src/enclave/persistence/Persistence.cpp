#include "Persistence.h"
#include "EUtils.h"
#include "sgx_tseal.h"
#include "EJson.h"

using namespace std;

void inner_ocall_persist_get(crust_status_t* crust_status, const char *key, uint8_t **value, size_t *value_len);

/**
 * @description: Add value by key
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Add status
 */
crust_status_t persist_add(std::string key, const uint8_t *value, size_t value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    crust_status = seal_data_mrenclave(value, value_len, &p_sealed_data, &sealed_data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    ocall_persist_add(&crust_status, key.c_str(), (uint8_t *)p_sealed_data, sealed_data_size);
    free(p_sealed_data);

    return crust_status;
}

/**
 * @description: Delete value by key
 * @param key -> Pointer to key
 * @return: Delete status
 */
crust_status_t persist_del(std::string key)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    ocall_persist_del(&crust_status, key.c_str());

    return crust_status;
}

/**
 * @description: Update value by key
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Update status
 */
crust_status_t persist_set(std::string key, const uint8_t *value, size_t value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sealed_data_t *p_sealed_data = NULL;
    uint8_t *p_sealed_data_u = NULL;
    size_t sealed_data_size = 0;
    crust_status = seal_data_mrenclave(value, value_len, &p_sealed_data, &sealed_data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    p_sealed_data_u = (uint8_t *)p_sealed_data;

    if (sealed_data_size > OCALL_STORE_THRESHOLD)
    {
        // Data size larger than default size
        size_t offset = 0;
        uint32_t part_size = 0;
        uint32_t index = 0;
        while (sealed_data_size > offset)
        {
            part_size = std::min((uint32_t)(sealed_data_size - offset), (uint32_t)OCALL_STORE_THRESHOLD);
            std::string cur_key = key + "_" + std::to_string(index);
            ocall_persist_set(&crust_status, cur_key.c_str(), reinterpret_cast<const uint8_t *>(p_sealed_data_u + offset), part_size);
            if (CRUST_SUCCESS != crust_status)
            {
                log_err("Store part data to DB failed!\n");
                goto cleanup;
            }
            offset += part_size;
            index++;
        }
        std::string sum_key = key + "_sum";
        json::JSON sum_json;
        sum_json[PERSIST_SUM] = index;
        sum_json[PERSIST_SIZE] = sealed_data_size;
        std::string sum_str = sum_json.dump();
        remove_char(sum_str, '\\');
        remove_char(sum_str, '\n');
        remove_char(sum_str, ' ');
        ocall_persist_set(&crust_status, sum_key.c_str(), reinterpret_cast<const uint8_t *>(sum_str.c_str()), sum_str.size());
        if (CRUST_SUCCESS != crust_status)
        {
            log_err("Store pieces information failed!\n");
            goto cleanup;
        }
    }
    else
    {
        // Delete old data
        std::string sum_key = key + "_sum";
        uint8_t *p_sum_key = NULL;
        size_t sum_key_len = 0;
        inner_ocall_persist_get(&crust_status, sum_key.c_str(), &p_sum_key, &sum_key_len);
        if (CRUST_SUCCESS == crust_status)
        {
            json::JSON sum_json = json::JSON::Load(std::string(reinterpret_cast<char *>(p_sum_key), sum_key_len));
            free(p_sum_key);
            uint32_t piece_num = sum_json[PERSIST_SUM].ToInt();
            for (uint32_t i = 0; i < piece_num; i++)
            {
                std::string del_key = key + "_" + std::to_string(i);
                persist_del(del_key);
            }
            persist_del(sum_key);
        }
        // Set new data
        ocall_persist_set(&crust_status, key.c_str(), (uint8_t *)p_sealed_data, sealed_data_size);
    }


cleanup:
    if (p_sealed_data != NULL)
    {
        free(p_sealed_data);
    }

    return crust_status;
}

/**
 * @description: Update value by key without seal
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Update status
 */
crust_status_t persist_set_unsafe(std::string key, const uint8_t *value, size_t value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (value_len > OCALL_STORE_THRESHOLD)
    {
        size_t offset = 0;
        size_t part_size = 0;
        uint32_t index = 0;
        while (value_len > offset)
        {
            part_size = std::min(value_len - offset, (size_t)OCALL_STORE_THRESHOLD);
            std::string cur_key = key + "_" + std::to_string(index);
            ocall_persist_set(&crust_status, cur_key.c_str(), reinterpret_cast<const uint8_t *>(value + offset), part_size);
            offset += part_size;
            index++;
        }
        std::string sum_key = key + "_sum";
        json::JSON sum_json;
        sum_json[PERSIST_SUM] = index;
        sum_json[PERSIST_SIZE] = value_len;
        std::string sum_str = sum_json.dump();
        remove_char(sum_str, '\\');
        remove_char(sum_str, '\n');
        remove_char(sum_str, ' ');
        ocall_persist_set(&crust_status, sum_key.c_str(), reinterpret_cast<const uint8_t *>(sum_str.c_str()), sum_str.size());
    }
    else
    {
        // Delete old data
        std::string sum_key = key + "_sum";
        uint8_t *p_sum_key = NULL;
        size_t sum_key_len = 0;
        inner_ocall_persist_get(&crust_status, sum_key.c_str(), &p_sum_key, &sum_key_len);
        if (CRUST_SUCCESS == crust_status)
        {
            json::JSON sum_json = json::JSON::Load(p_sum_key, sum_key_len);
            free(p_sum_key);
            uint32_t piece_num = sum_json[PERSIST_SUM].ToInt();
            for (uint32_t i = 0; i < piece_num; i++)
            {
                std::string del_key = key + "_" + std::to_string(i);
                persist_del(del_key);
            }
            persist_del(sum_key);
        }
        // Set new data
        ocall_persist_set(&crust_status, key.c_str(), value, value_len);
    }

    return crust_status;
}

/**
 * @description: Get value by key from ocall
 * @param crust_status -> status
 * @param key -> Pointer to key
 * @param value -> Pointer points to value
 * @param value_len -> Pointer to value length
 */
void inner_ocall_persist_get(crust_status_t* crust_status, const char *key, uint8_t **value, size_t *value_len)
{
    uint8_t *temp_value = NULL;
    size_t temp_value_len = 0;

    ocall_persist_get(crust_status, key, &temp_value, &temp_value_len);
    if (CRUST_SUCCESS != *crust_status)
    {
        *value = NULL;
        *value_len = 0;
        return;
    }

    *value = (uint8_t*)enc_malloc(temp_value_len);
    if(*value == NULL)
    {
        ocall_free_outer_buffer(crust_status, &temp_value);
        if (CRUST_SUCCESS != *crust_status)
        {
            return;
        }

        *crust_status = CRUST_MALLOC_FAILED;
        return;
    }

    memset(*value, 0, temp_value_len);
    memcpy(*value, temp_value, temp_value_len);
    *value_len = temp_value_len;

    ocall_free_outer_buffer(crust_status, &temp_value);
    if (CRUST_SUCCESS != *crust_status)
    {
        free(*value);
        *value = NULL;
        *value_len = 0;
        return;
    }
}

/**
 * @description: Get value by key
 * @param key -> Pointer to key
 * @param value -> Pointer points to value
 * @param value_len -> Pointer to value length
 * @return: Get status
 */
crust_status_t persist_get(std::string key, uint8_t **value, size_t *value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    uint8_t *p_sealed_data = NULL;
    size_t sealed_data_size = 0;
    sgx_sealed_data_t *p_sealed_data_r = NULL;
    uint8_t *p_sealed_data_u = NULL;

    // Try to get sum information
    std::string sum_key = key + "_sum";
    uint8_t *p_sum_key = NULL;
    size_t sum_key_len = 0;
    inner_ocall_persist_get(&crust_status, sum_key.c_str(), &p_sum_key, &sum_key_len);
    if (CRUST_SUCCESS == crust_status)
    {
        // Get sum info successfully, obtain sealed data from pieces
        json::JSON sum_json = json::JSON::Load(std::string(reinterpret_cast<char *>(p_sum_key), sum_key_len));
        // Set available flag
        free(p_sum_key);
        // Allocate buffer for sealed data
        sealed_data_size = sum_json[PERSIST_SIZE].ToInt();
        uint32_t piece_num = sum_json[PERSIST_SUM].ToInt();
        p_sealed_data_r = (sgx_sealed_data_t*)enc_malloc(sealed_data_size);
        if (p_sealed_data_r == NULL)
        {
            log_err("Malloc memory failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        memset(p_sealed_data_r, 0, sealed_data_size);
        p_sealed_data_u = (uint8_t *)p_sealed_data_r;
        // Get sealed data from pieces
        size_t offset = 0;
        for (uint32_t i = 0; i < piece_num; i++)
        {
            std::string cur_key = key + "_" + std::to_string(i);
            uint8_t *p_part_data = NULL;
            size_t part_data_size = 0;
            inner_ocall_persist_get(&crust_status, cur_key.c_str(), &p_part_data, &part_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                log_err("Get part data failed!Part key:%s\n", cur_key.c_str());
                free(p_sealed_data_r);
                return crust_status;
            }
            memcpy(p_sealed_data_u + offset, p_part_data, part_data_size);
            free(p_part_data);
            offset += part_data_size;
        }
    }
    else
    {
        inner_ocall_persist_get(&crust_status, key.c_str(), &p_sealed_data, &sealed_data_size);
        if (CRUST_SUCCESS != crust_status)
        {
            return crust_status;
        }
        // Allocate buffer for sealed data
        p_sealed_data_r = (sgx_sealed_data_t*)enc_malloc(sealed_data_size);
        if (p_sealed_data_r == NULL)
        {
            log_err("Malloc memory failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        memset(p_sealed_data_r, 0, sealed_data_size);
        memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
        free(p_sealed_data);
    }

    // Get unsealed data
    uint32_t unsealed_data_size = sgx_get_encrypt_txt_len(p_sealed_data_r);
    uint8_t *p_unsealed_data = (uint8_t*)enc_malloc(unsealed_data_size);
    if (p_unsealed_data == NULL)
    {
        log_err("Malloc memory failed!\n");
        goto cleanup;
    }
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

/**
 * @description: Get value by key
 * @param key -> Pointer to key
 * @param value -> Pointer points to value
 * @param value_len -> Pointer to value length
 * @return: Get status
 */
crust_status_t persist_get_unsafe(std::string key, uint8_t **value, size_t *value_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    uint8_t *data = NULL;
    uint8_t *p_data = NULL;
    size_t data_len = 0;
    // Try to get sum information
    std::string sum_key = key + "_sum";
    uint8_t *p_sum_key = NULL;
    size_t sum_key_len = 0;
    inner_ocall_persist_get(&crust_status, sum_key.c_str(), &p_sum_key, &sum_key_len);
    if (CRUST_SUCCESS == crust_status)
    {
        // Get sum info successfully, obtain data from pieces
        json::JSON sum_json = json::JSON::Load(std::string(reinterpret_cast<char *>(p_sum_key), sum_key_len));
        // Set available flag
        free(p_sum_key);
        // Allocate buffer for data
        uint32_t piece_num = sum_json[PERSIST_SUM].ToInt();
        data_len = sum_json[PERSIST_SIZE].ToInt();
        p_data = (uint8_t *)enc_malloc(data_len);
        if (p_data == NULL)
        {
            log_err("Malloc memory failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        memset(p_data, 0, data_len);
        // Get sealed data from pieces
        size_t offset = 0;
        for (uint32_t i = 0; i < piece_num; i++)
        {
            std::string cur_key = key + "_" + std::to_string(i);
            uint8_t *p_part_data = NULL;
            size_t part_data_size = 0;
            inner_ocall_persist_get(&crust_status, cur_key.c_str(), &p_part_data, &part_data_size);
            memcpy(p_data + offset, p_part_data, part_data_size);
            free(p_part_data);
            offset += part_data_size;
        }
    }
    else
    {
        inner_ocall_persist_get(&crust_status, key.c_str(), &data, &data_len);
        if (CRUST_SUCCESS != crust_status)
        {
            return crust_status;
        }
        // Allocate buffer for sealed data
        p_data = (uint8_t *)enc_malloc(data_len);
        if (p_data == NULL)
        {
            log_err("Malloc memory failed!\n");
            return CRUST_MALLOC_FAILED;
        }
        memset(p_data, 0, data_len);
        memcpy(p_data, data, data_len);
        free(data);
    }

    *value = p_data;
    *value_len = data_len;

    return crust_status;
}
