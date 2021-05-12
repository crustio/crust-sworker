#include "EnclaveData.h"
#include "ECalls.h"

crust::Log *p_log = crust::Log::get_instance();
EnclaveData *EnclaveData::enclavedata = NULL;
std::mutex enclave_id_info_mutex;

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
    sgx_status_t sgx_status = SGX_SUCCESS;
    if (SGX_SUCCESS != (sgx_status = Ecall_id_get_info(global_eid)))
    {
        p_log->err("Get id info failed! Error code:%lx\n", sgx_status);
        return "";
    }

    SafeLock sl(enclave_id_info_mutex);
    sl.lock();
    return enclave_id_info;
}

/**
 * @description: Set enclave identity information
 * @param id_info -> Identity information
 */
void EnclaveData::set_enclave_id_info(std::string id_info)
{
    SafeLock sl(enclave_id_info_mutex);
    sl.lock();
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
 * @description: Add sealed file info
 * @param cid -> IPFS content id
 * @param info -> Related file info
 */
void EnclaveData::add_sealed_file_info(std::string cid, std::string info)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    if (is_sealed_file_dup(cid, false))
    {
        p_log->warn("file(%s) has been sealed!\n", cid.c_str());
        return;
    }

    this->sealed_file[FILE_TYPE_VALID][cid] = info;
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
    std::string type;
    if (this->sealed_file[FILE_TYPE_VALID].hasKey(cid) != 0)
    {
        type = FILE_TYPE_VALID;
    }
    else if (this->sealed_file[FILE_TYPE_LOST].hasKey(cid) != 0)
    {
        type = FILE_TYPE_LOST;
    }

    if (type.compare("") == 0)
    {
        return "";
    }

    return this->sealed_file[type][cid].dump();
}

/**
 * @description: Change sealed file info from old type to new type
 * @param cid -> File root cid
 * @param old_type -> Old file type
 * @param new_type -> New file type
 */
void EnclaveData::change_sealed_file_type(const std::string &cid, const std::string &old_type, const std::string &new_type)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    if (this->sealed_file[old_type].hasKey(cid) == 0)
    {
        return ;
    }
    this->sealed_file[new_type][cid] = this->sealed_file[old_type][cid];
    this->sealed_file[old_type].ObjectRange().object->erase(cid);
}

/**
 * @description: Get all sealed file information
 * @return: All sealed file information
 */
std::string EnclaveData::get_sealed_file_info_all()
{
    std::string ans;
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();

    if (this->sealed_file.size() <= 0)
    {
        return "{}";
    }

    ans = this->sealed_file.dump();

    replace(ans, "\"{", "{");
    replace(ans, "}\"", "}");
    remove_char(ans,'\\');

    return ans;
}

/**
 * @description: Check if file is duplicated
 * @param cid -> IPFS content id
 * @param locked -> Lock sealed_file or not
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
    if (this->sealed_file[FILE_TYPE_VALID].hasKey(cid))
    {
        this->sealed_file[FILE_TYPE_VALID].ObjectRange().object->erase(cid);
    }
    if (this->sealed_file[FILE_TYPE_LOST].hasKey(cid))
    {
        this->sealed_file[FILE_TYPE_LOST].ObjectRange().object->erase(cid);
    }
}

/**
 * @description: Restore sealed file information
 * @param valid_data -> All valid file information
 * @param valid_size -> All valid file information size
 * @param lost_data -> All lost file information
 * @param lost_size -> All lost file information size
 */
void EnclaveData::restore_sealed_file_info(const uint8_t *valid_data, size_t valid_size, const uint8_t *lost_data, size_t lost_size)
{
    this->sealed_file_mutex.lock();
    json::JSON valid_json = json::JSON::Load(valid_data, valid_size);
    json::JSON lost_json = json::JSON::Load(lost_data, lost_size);
    this->sealed_file[FILE_TYPE_VALID] = valid_json;
    this->sealed_file[FILE_TYPE_LOST] = lost_json;
    this->sealed_file_mutex.unlock();
}

/**
 * @description: Set srd information
 * @param data -> Pointer to srd info data
 * @param data_size -> Srd info data size
 */
void EnclaveData::set_srd_info(const uint8_t *data, size_t data_size)
{
    this->srd_info_mutex.lock();
    this->srd_info = json::JSON::Load(data, data_size);
    this->srd_info_mutex.unlock();
}

/**
 * @description: Get srd information
 * @return: Srd information
 */
json::JSON EnclaveData::get_srd_info()
{
    SafeLock sl(this->srd_info_mutex);
    sl.lock();
    return this->srd_info;
}

/**
 * @description: Generate workload
 * @param srd_task -> Indicate recovered srd task from restart
 * @return: Workload in string
 */
std::string EnclaveData::gen_workload_str(long srd_task)
{
    json::JSON wl_json = this->gen_workload_for_print(srd_task);
    std::string wl_str = wl_json.dump();
    replace(wl_str, "\"{", "{");
    replace(wl_str, ": \" ", ":  ");
    replace(wl_str, "}\"", "}");
    replace(wl_str, "\\n", "\n");
    remove_char(wl_str, '\\');
    return wl_str;
}

/**
 * @description: Generate workload
 * @param srd_task -> Indicate recovered srd task from restart
 * @return: Workload in json
 */
json::JSON EnclaveData::gen_workload_for_print(long srd_task)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    EnclaveData *ed = EnclaveData::get_instance();
    // Get srd info
    if (SGX_SUCCESS != (sgx_status = Ecall_get_workload(global_eid)))
    {
        p_log->warn("Get workload failed! Error code:%lx\n", sgx_status);
    }
    json::JSON wl_json = json::JSON::Load(get_enclave_workload());
    if (wl_json.size() == -1)
    {
        return "Get workload failed!";
    }
    json::JSON disk_json = get_disk_info();
    int disk_avail_for_srd = 0;
    int disk_avail = 0;
    int disk_volume = 0;
    std::string disk_info;
    disk_info.append("{\n");
    for (int i = 0; i < disk_json.size(); i++)
    {
        std::string uuid = ed->get_uuid(disk_json[i][WL_DISK_PATH].ToString());
        std::string disk_path = disk_json[i][WL_DISK_PATH].ToString();
        uint32_t buffer_sz = disk_path.size() + 128;
        char buffer[buffer_sz];
        memset(buffer, 0, buffer_sz);
        sprintf(buffer, "  \"%s\" : { \"srd\" : %ld, \"srd_avail\" : %ld, \"avail\" : %ld, \"volumn\" : %ld }", 
                disk_path.c_str(),
                wl_json[WL_SRD][WL_SRD_DETAIL][uuid].ToInt(),
                disk_json[i][WL_DISK_AVAILABLE_FOR_SRD].ToInt(),
                disk_json[i][WL_DISK_AVAILABLE].ToInt(),
                disk_json[i][WL_DISK_VOLUME].ToInt());
        disk_info.append(buffer);
        if (i != disk_json.size() - 1)
        {
            disk_info.append(",");
        }
        disk_info.append("\n");
        disk_avail += disk_json[i][WL_DISK_AVAILABLE].ToInt();
        disk_avail_for_srd += disk_json[i][WL_DISK_AVAILABLE_FOR_SRD].ToInt();
        disk_volume += disk_json[i][WL_DISK_VOLUME].ToInt();
    }
    disk_info.append("}");
    std::string srd_info;
    srd_info.append("{\n")
            .append("\"" WL_SRD_COMPLETE "\" : ").append(std::to_string(wl_json[WL_SRD][WL_SRD_COMPLETE].ToInt())).append(",\n")
            .append("\"" WL_SRD_REMAINING_TASK "\" : ").append(std::to_string(wl_json[WL_SRD][WL_SRD_REMAINING_TASK].ToInt() + srd_task)).append(",\n")
            .append("\"" WL_DISK_AVAILABLE_FOR_SRD "\" : ").append(std::to_string(disk_avail_for_srd)).append(",\n")
            .append("\"" WL_DISK_AVAILABLE "\" : ").append(std::to_string(disk_avail)).append(",\n")
            .append("\"" WL_DISK_VOLUME "\" : ").append(std::to_string(disk_volume)).append(",\n")
            .append("\"" WL_SRD_DETAIL "\" : ").append(disk_info).append("\n")
            .append("}");
    wl_json[WL_SRD] = srd_info;
    // Get file info
    json::JSON file_info = wl_json[WL_FILES];
    json::JSON n_file_info;
    char buf[128];
    int space_num = 0;
    for (auto it = file_info.ObjectRange().begin(); it != file_info.ObjectRange().end(); it++)
    {
        space_num = std::max(space_num, (int)it->first.size());
    }
    for (auto it = file_info.ObjectRange().begin(); it != file_info.ObjectRange().end(); it++)
    {
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%s{  \"num\" : %-6ld, \"size\" : %ld  }",
                std::string(space_num - it->first.size(), ' ').c_str(), it->second["num"].ToInt(), it->second["size"].ToInt());
        n_file_info[it->first] = std::string(buf);
    }

    wl_json[WL_FILES] = n_file_info;
    return wl_json;
}

/**
 * @description: Generate workload
 * @param srd_task -> Indicate recovered srd task from restart
 * @return: Workload in json
 */
json::JSON EnclaveData::gen_workload(long srd_task)
{
    return json::JSON::Load(gen_workload_str(srd_task));
}

/**
 * @description: Construct uuid and disk path map
 */
void EnclaveData::construct_uuid_disk_path_map()
{
    for (auto path : Config::get_instance()->get_data_paths())
    {
        check_or_init_disk(path);
    }
}

/**
 * @description: Set mapping between uuid and disk path
 * @param uuid -> Disk uuid
 * @param path -> Disk path
 */
void EnclaveData::set_uuid_disk_path_map(std::string uuid, std::string path)
{
    this->uuid_to_disk_path[uuid] = path;
    this->disk_path_to_uuid[path] = uuid;
}

/**
 * @description: Get uuid by disk path
 * @param path -> Disk path
 * @return: Disk uuid
 */
std::string EnclaveData::get_uuid(std::string path)
{
    return this->disk_path_to_uuid[path];
}

/**
 * @description: Get disk path by uuid
 * @param uuid -> Disk uuid
 * @return: Disk path
 */
std::string EnclaveData::get_disk_path(std::string uuid)
{
    return this->uuid_to_disk_path[uuid];
}

/**
 * @description: Check if related uuid is existed in given path
 * @param path -> Disk path
 * @return: Is the mapping existed by given disk path
 */
bool EnclaveData::is_disk_exist(std::string path)
{
    return this->disk_path_to_uuid.find(path) != this->disk_path_to_uuid.end();
}

/**
 * @description: Check if related path is existed in given uuid
 * @param uuid -> Disk uuid
 * @return: Is the mapping existed by given uuid
 */
bool EnclaveData::is_uuid_exist(std::string uuid)
{
    return this->uuid_to_disk_path.find(uuid) != this->uuid_to_disk_path.end();
}
