# include "PersistOCalls.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Add record to DB
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Add status
 */
crust_status_t ocall_persist_add(const char *key, const uint8_t *value, size_t value_len)
{
    return crust::DataBase::get_instance()->add(std::string(key), std::string((const char*)value, value_len));
}

/**
 * @description: Add keys to indicate key, the value got by key must be a json object
 * @param key -> Pointer to key
 * @param keys -> To be added keys array
 * @param keys_len -> Keys array length
 * @return: Add status
 */
crust_status_t ocall_persist_add_keys(const char *key, const char *keys, size_t keys_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::DataBase *db = crust::DataBase::get_instance();
    std::string json_str;
    if (CRUST_SUCCESS != (crust_status = db->get(std::string(key), json_str)))
    {
        p_log->warn("Add key:%s failed! Error code:%lx\n", key, crust_status);
    }
    json::JSON det_json = json::JSON::Load(json_str);

    json::JSON add_keys_json = json::JSON::Load(std::string(keys, keys_len));
    for (auto it : add_keys_json.ArrayRange())
    {
        det_json[it.ToString()] = true;
    }

    if (CRUST_SUCCESS != (crust_status = db->set(key, det_json.dump())))
    {
        p_log->err("Add key:%s failed! Error code:%lx\n", key, crust_status);
        return crust_status;
    }

    return crust_status;
}

/**
 * @description: Delete record from DB
 * @param key -> Pointer to key
 * @return: Delete status
 */
crust_status_t ocall_persist_del(const char *key)
{
    return crust::DataBase::get_instance()->del(std::string(key));
}

/**
 * @description: Delete json value by keys
 * @param key -> DB key, corresponding value must be json format
 * @param keys -> To be deleted Key-value keys
 * @param keys_len -> Keys length
 * @return: Delete status
 */
crust_status_t ocall_persist_del_keys(const char *key, const char *keys, size_t keys_len)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::DataBase *db = crust::DataBase::get_instance();
    std::string json_str;
    if (CRUST_SUCCESS != (crust_status = db->get(std::string(key), json_str)))
    {
        p_log->warn("Get key:%s failed! Error code:%lx\n", key, crust_status);
    }

    json::JSON det_json = json::JSON::Load(json_str);
    auto p_obj = det_json.ObjectRange();
    json::JSON del_keys_json = json::JSON::Load(std::string(keys, keys_len));
    for (auto it : del_keys_json.ArrayRange())
    {
        p_obj.object->erase(it.ToString());
    }

    std::string det_str = det_json.dump();
    if (CRUST_SUCCESS != (crust_status = db->set(key, det_str)))
    {
        p_log->err("Update key:%s failed! Error code:%lx\n", key, crust_status);
        return crust_status;
    }

    return crust_status;
}

/**
 * @description: Update record in DB
 * @param key -> Pointer to key
 * @param value -> Pointer to value
 * @param value_len -> value length
 * @return: Update status
 */
crust_status_t ocall_persist_set(const char *key, const uint8_t *value, size_t value_len)
{
    return crust::DataBase::get_instance()->set(std::string(key), std::string((const char*)value, value_len));
}

/**
 * @description: Get record from DB
 * @param key -> Pointer to key
 * @param value -> Pointer points to pointer to value
 * @param value_len -> value length
 * @return: Get status
 */
crust_status_t ocall_persist_get(const char *key, uint8_t **value, size_t *value_len)
{
    std::string val;
    crust_status_t crust_status = crust::DataBase::get_instance()->get(std::string(key), val);
    if (CRUST_SUCCESS != crust_status)
    {
        *value_len = 0;
        return crust_status;
    }
    
    *value_len = val.size();
    *value = (uint8_t*)malloc(*value_len);
    memcpy(*value, val.c_str(), *value_len);

    return crust_status;
}
