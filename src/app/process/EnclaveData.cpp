#include "EnclaveData.h"
#include "ECalls.h"

crust::Log *p_log = crust::Log::get_instance();
EnclaveData *EnclaveData::enclavedata = NULL;

extern sgx_enclave_id_t global_eid;

/**
 * @desination: Single instance class function to get instance
 * @return: Enclave data instance
 */
EnclaveData *EnclaveData::get_instance()
{
    if (EnclaveData::enclavedata == NULL)
    {
        EnclaveData::enclavedata = new EnclaveData();
    }

    return EnclaveData::enclavedata;
}

/**
 * @description: Get enclave identity information
 * @return: Enclave information
 */
std::string EnclaveData::get_enclave_id_info()
{
    return enclave_id_info;
}

/**
 * @description: Set enclave identity information
 * @param id_info -> Identity information
 */
void EnclaveData::set_enclave_id_info(std::string id_info)
{
    enclave_id_info = id_info;
}

/**
 * @description: Get workload
 * @return: Workload
 */
std::string EnclaveData::get_enclave_workload()
{
    return enclave_workload;
}

/**
 * @description: Set workload
 * @param workload -> Sworker workload
 */
void EnclaveData::set_enclave_workload(std::string workload)
{
    enclave_workload = workload;
}

/**
 * @description: Get upgrade data
 * @return: Upgrade data
 */
std::string EnclaveData::get_upgrade_data()
{
    return upgrade_data;
}

/**
 * @description: Set upgrade data
 * @param data -> Upgrade data
 */
void EnclaveData::set_upgrade_data(std::string data)
{
    upgrade_data = data;
}

/**
 * @description: Get upgrade status
 * @return: Upgrade status
 */
upgrade_status_t EnclaveData::get_upgrade_status()
{
    upgrade_status_mutex.lock();
    upgrade_status_t status = upgrade_status;
    upgrade_status_mutex.unlock();

    return status;
}

/**
 * @description: Set upgrade status
 * @param status -> Upgrade status
 */
void EnclaveData::set_upgrade_status(upgrade_status_t status)
{
    SafeLock sl(upgrade_status_mutex);
    sl.lock();
    if (upgrade_status == status)
    {
        return;
    }
    upgrade_status = status;
    switch(upgrade_status)
    {
        case UPGRADE_STATUS_NONE:
            p_log->debug("Set upgrade status to: UPGRADE_STATUS_NONE\n");
            break;
        case UPGRADE_STATUS_STOP_WORKREPORT:
            p_log->debug("Set upgrade status to: UPGRADE_STATUS_STOP_WORKREPORT\n");
            break;
        case UPGRADE_STATUS_PROCESS:
            p_log->debug("Set upgrade status to: UPGRADE_STATUS_PROCESS\n");
            break;
        case UPGRADE_STATUS_END:
            p_log->debug("Set upgrade status to: UPGRADE_STATUS_END\n");
            break;
        case UPGRADE_STATUS_COMPLETE:
            p_log->debug("Set upgrade status to: UPGRADE_STATUS_COMPLETE\n");
            break;
        case UPGRADE_STATUS_EXIT:
            p_log->debug("Set upgrade status to: UPGRADE_STATUS_EXIT\n");
            break;
        default:
            p_log->warn("Unknown upgrade status!\n");
    }
    sl.unlock();

    if (UPGRADE_STATUS_NONE == get_upgrade_status())
    {
        Ecall_disable_upgrade(global_eid);
    }
}

/**
 * @description: Add unsealed data
 * @param root -> Unsealed data root hash
 * @param data -> Pointer to unsealed data
 * @param data_size -> Unsealed data size
 */
void EnclaveData::add_unsealed_data(std::string root, uint8_t *data, size_t data_size)
{
    unsealed_data_mutex.lock();
    unsealed_data_um[root] = std::make_pair(data, data_size);
    unsealed_data_mutex.unlock();
}

/**
 * @description: Get unsealed data
 * @param root -> Unsealed data root hash
 * @param data -> Pointer to unsealed data
 * @param data_size -> Unsealed data size
 */
void EnclaveData::get_unsealed_data(std::string root, const uint8_t **data, size_t *data_size)
{
    SafeLock sl(unsealed_data_mutex);
    sl.lock();
    if (unsealed_data_um.find(root) == unsealed_data_um.end())
    {
        return;
    }
    auto res = unsealed_data_um[root];
    *data = res.first;
    *data_size = res.second;
}

/**
 * @description: Delete unsealed data
 * @param root -> Unsealed data hash
 */
void EnclaveData::del_unsealed_data(std::string root)
{
    SafeLock sl(unsealed_data_mutex);
    sl.lock();
    if (unsealed_data_um.find(root) == unsealed_data_um.end())
    {
        return;
    }
    auto res = unsealed_data_um[root];
    if (res.first != NULL)
    {
        free(res.first);
    }
    unsealed_data_um.erase(root);
}
