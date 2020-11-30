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
 * @return: Unsealed data
 */
std::string EnclaveData::get_unsealed_data(std::string root)
{
    SafeLock sl(unsealed_data_mutex);
    sl.lock();
    if (unsealed_data_um.find(root) == unsealed_data_um.end())
    {
        return "";
    }
    auto res = unsealed_data_um[root];

    return std::string(reinterpret_cast<const char *>(res.first), res.second);
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

/**
 * @description: Add sealed file info
 * @param cid -> IPFS content id
 * @param file_size -> Related file size
 */
void EnclaveData::add_sealed_file_info(std::string cid, size_t file_size)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    if (is_sealed_file_dup(cid, false))
    {
        p_log->warn("file(%s) has been sealed!\n", cid.c_str());
        return;
    }

    this->sealed_file[cid] = std::string("{ \"") + FILE_SIZE + "\" : " + std::to_string(file_size) + " }";

    crust::DataBase::get_instance()->set(DB_FILE_INFO, this->sealed_file.dump());
}

/**
 * @description: Get sealed file information
 * @param cid -> IPFS content id
 * @return: Sealed file information
 */
std::string EnclaveData::get_sealed_file_info(std::string cid)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    json::JSON file_info;
    if (this->sealed_file.hasKey(cid) == 0)
    {
        return "";
    }
    file_info[cid] = this->sealed_file[cid];
    std::string ans = file_info.dump();
    remove_char(ans, '\n');
    remove_char(ans, '\\');
    remove_char(ans, ' ');
    replace(ans, "\"{", "{");
    replace(ans, "}\"", "}");

    return ans;
}

/**
 * @description: Get all sealed file information
 * @return: All sealed file information
 */
std::string EnclaveData::get_sealed_file_info_all()
{
    std::string ans;
    this->sealed_file_mutex.lock();
    ans = this->sealed_file.dump();
    this->sealed_file_mutex.unlock();

    replace(ans, "\"{", "{");
    replace(ans, "}\"", "}");
    remove_char(ans,'\\');

    return ans;
}

/**
 * @description: Check if file is duplicated
 * @param cid -> IPFS content id
 * @return: Duplicated or not
 */
bool EnclaveData::is_sealed_file_dup(std::string cid, bool locked)
{
    SafeLock sl(this->sealed_file_mutex);
    if (locked)
    {
        sl.lock();
    }

    if (this->sealed_file.hasKey(cid))
    {
        return true;
    }

    return false;
}

/**
 * @description: Delete sealed file information
 * @param cid -> IPFS content id
 */
void EnclaveData::del_sealed_file_info(std::string cid)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    this->sealed_file.ObjectRange().object->erase(cid);
    crust::DataBase::get_instance()->set(DB_FILE_INFO, this->sealed_file.dump());
}

/**
 * @description: Restore sealed file information
 */
void EnclaveData::restore_sealed_file_info()
{
    this->sealed_file_mutex.lock();
    // Restore file information
    std::string file_info;
    crust::DataBase::get_instance()->get(DB_FILE_INFO, file_info);
    p_log->info("file info:%s\n", file_info.c_str());
    this->sealed_file = json::JSON::Load(file_info);
    this->sealed_file_mutex.unlock();
}
