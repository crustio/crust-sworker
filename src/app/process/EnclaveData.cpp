#include "EnclaveData.h"
#include "ECalls.h"

crust::Log *p_log = crust::Log::get_instance();
EnclaveData *EnclaveData::enclavedata = NULL;
std::mutex enclavedata_mutex;

extern sgx_enclave_id_t global_eid;

/**
 * @desination: Single instance class function to get instance
 * @return: Enclave data instance
 */
EnclaveData *EnclaveData::get_instance()
{
    if (EnclaveData::enclavedata == NULL)
    {
        enclavedata_mutex.lock();
        if (EnclaveData::enclavedata == NULL)
        {
            EnclaveData::enclavedata = new EnclaveData();
        }
        enclavedata_mutex.unlock();
    }

    return EnclaveData::enclavedata;
}

/**
 * @description: Set enclave identity information
 * @param id_info -> Identity information
 */
void EnclaveData::set_enclave_id_info(std::string id_info)
{
    this->enclave_id_info_mutex.lock();
    this->enclave_id_info = id_info;
    this->enclave_id_info_mutex.unlock();
}

/**
 * @description: Get enclave identity information
 * @return: Enclave information
 */
std::string EnclaveData::get_enclave_id_info()
{
    SafeLock sl(this->enclave_id_info_mutex);
    sl.lock();
    if (this->enclave_id_info.size() == 0)
    {
        sl.unlock();
        if (SGX_SUCCESS != Ecall_id_get_info(global_eid))
        {
            p_log->err("Get id info from enclave failed!\n");
            return "";
        }
        sl.lock();
        return this->enclave_id_info;
    }

    return this->enclave_id_info;
}

/**
 * @description: Store workreport
 * @param data -> Pointer to workreport data
 * @param data_size -> Workreport data size
 */
void EnclaveData::set_workreport(const uint8_t *data, size_t data_size)
{
    workreport_mutex.lock();
    this->workreport = std::string(reinterpret_cast<const char *>(data), data_size);
    workreport_mutex.unlock();
}

/**
 * @description: Get workreport
 * @return: Workreport
 */
std::string EnclaveData::get_workreport()
{
    SafeLock sl(workreport_mutex);
    sl.lock();
    return this->workreport;
}

/**
 * @description: Set srd information
 * @param data -> Pointer to srd info data
 * @param data_size -> Srd info data size
 */
void EnclaveData::set_srd_info(const uint8_t *data, size_t data_size)
{
    this->srd_info_mutex.lock();
    this->srd_info = json::JSON::Load_unsafe(data, data_size);
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
 * @description: Add pending file size
 * @param cid -> File content id
 * @param size -> File size
 */
void EnclaveData::add_pending_file_size(std::string cid, long size)
{
    this->pending_file_size_um_mutex.lock();
    this->pending_file_size_um[cid] += size;
    this->pending_file_size_um_mutex.unlock();
}

/**
 * @description: Get pending file size
 * @param cid -> File content id
 * @return: Pending file size
 */
long EnclaveData::get_pending_file_size(std::string cid)
{
    SafeLock sl(this->pending_file_size_um_mutex);
    sl.lock();
    return this->pending_file_size_um[cid];
}

/**
 * @description: Delete pending file
 * @param cid -> File content id
 */
void EnclaveData::del_pending_file_size(std::string cid)
{
    this->pending_file_size_um_mutex.lock();
    this->pending_file_size_um.erase(cid);
    this->pending_file_size_um_mutex.unlock();
}

/**
 * @description: Get upgrade data
 * @return: Upgrade data
 */
std::string EnclaveData::get_upgrade_data()
{
    SafeLock sl(this->upgrade_data_mutex);
    sl.lock();
    return upgrade_data;
}

/**
 * @description: Set upgrade data
 * @param data -> Upgrade data
 */
void EnclaveData::set_upgrade_data(std::string data)
{
    this->upgrade_data_mutex.lock();
    this->upgrade_data = data;
    this->upgrade_data_mutex.unlock();
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
            p_log->info("Set upgrade status to: UPGRADE_STATUS_NONE\n");
            break;
        case UPGRADE_STATUS_STOP_WORKREPORT:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_STOP_WORKREPORT\n");
            break;
        case UPGRADE_STATUS_PROCESS:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_PROCESS\n");
            break;
        case UPGRADE_STATUS_END:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_END\n");
            break;
        case UPGRADE_STATUS_COMPLETE:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_COMPLETE\n");
            break;
        case UPGRADE_STATUS_EXIT:
            p_log->info("Set upgrade status to: UPGRADE_STATUS_EXIT\n");
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
 * @description: Get upgrade status
 * @return: Upgrade status
 */
upgrade_status_t EnclaveData::get_upgrade_status()
{
    SafeLock sl(upgrade_status_mutex);
    sl.lock();
    return upgrade_status;
}

/**
 * @description: Add sealed file info
 * @param cid -> IPFS content id
 * @param type -> File type
 * @param info -> Related file info
 */
void EnclaveData::add_file_info(const std::string &cid, std::string type, std::string info)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    std::string c_type = type;
    if (type.compare(FILE_TYPE_PENDING) == 0)
    {
        info = "{ \"" FILE_PENDING_STIME "\" : " + std::to_string(get_seconds_since_epoch()) + " }";
    }

    if (type.compare(FILE_TYPE_VALID) == 0)
    {
        this->sealed_file[FILE_TYPE_PENDING].erase(cid);
    }

    this->sealed_file[type][cid] = info;
    sl.unlock();

    // Update file info
    SafeLock sl_file_info(this->file_info_mutex);
    sl_file_info.lock();
    remove_char(info, '\\');
    crust_status_t crust_status = CRUST_SUCCESS;
    json::JSON info_json = json::JSON::Load(&crust_status, info);
    if (CRUST_SUCCESS != crust_status)
    {
        p_log->debug("Parse adding file info failed! Error code:%lx\n", crust_status);
        return;
    }
    size_t file_size = 0;
    if (type.compare(FILE_TYPE_VALID) == 0)
    {
        this->file_info[FILE_TYPE_PENDING]["num"].AddNum(-1);
        file_size = info_json[FILE_SIZE].ToInt();
    }
    this->file_info[type]["num"].AddNum(1);
    this->file_info[type]["size"].AddNum(file_size);
}

/**
 * @description: Change sealed file info from old type to new type
 * @param cid -> File root cid
 * @param old_type -> Old file type
 * @param new_type -> New file type
 */
void EnclaveData::change_file_type(const std::string &cid, std::string old_type, std::string new_type)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    if (this->sealed_file.find(old_type) == this->sealed_file.end())
    {
        p_log->warn("Old type:%s no found!\n", old_type.c_str());
        return;
    }
    if (this->sealed_file[old_type].find(cid) == this->sealed_file[old_type].end())
    {
        p_log->warn("Old type:%s cid:%s not found!\n", old_type.c_str(), cid.c_str());
        return;
    }
    std::string info = this->sealed_file[old_type][cid];
    this->sealed_file[new_type][cid] = this->sealed_file[old_type][cid];
    this->sealed_file[old_type].erase(cid);
    sl.unlock();

    remove_char(info, '\\');
    json::JSON info_json = json::JSON::Load_unsafe(info);
    long new_size = 0;
    long old_size = 0;
    if (new_type.compare(FILE_TYPE_PENDING) != 0)
    {
        new_size = info_json[FILE_SIZE].ToInt();
    }
    if (old_type.compare(FILE_TYPE_PENDING) != 0)
    {
        old_size = info_json[FILE_SIZE].ToInt();
    }

    // Update file info
    this->file_info_mutex.lock();
    this->file_info[new_type]["num"].AddNum(1);
    this->file_info[new_type]["size"].AddNum(new_size);
    this->file_info[old_type]["num"].AddNum(-1);
    this->file_info[old_type]["size"].AddNum(-old_size);
    this->file_info_mutex.unlock();
}

/**
 * @description: Delete sealed file information
 * @param cid -> IPFS content id
 */
void EnclaveData::del_file_info(std::string cid)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    std::string info;
    std::string type;
    bool deleted = false;
    for (auto it = this->sealed_file.begin(); it != this->sealed_file.end(); it++)
    {
        if (it->second.find(cid) != it->second.end())
        {
            type = it->first;
            info = it->second[cid];
            it->second.erase(cid);
            deleted = true;
        }
    }
    sl.unlock();

    // Update file info
    if (deleted)
    {
        remove_char(info, '\\');
        json::JSON info_json = json::JSON::Load_unsafe(info);
        long file_size = 0;
        if (type.compare(FILE_TYPE_PENDING) != 0)
        {
            file_size = info_json[FILE_SIZE].ToInt();
        }
        this->file_info_mutex.lock();
        this->file_info[type]["num"].AddNum(-1);
        this->file_info[type]["size"].AddNum(-file_size);
        this->file_info_mutex.unlock();
    }
}

/**
 * @description: Delete sealed file information
 * @param cid -> IPFS content id
 * @param type -> File type
 */
void EnclaveData::del_file_info(std::string cid, std::string type)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    bool deleted = false;
    std::string info;
    if (this->sealed_file[type].find(cid) != this->sealed_file[type].end())
    {
        info = this->sealed_file[type][cid];
        this->sealed_file[type].erase(cid);
        deleted = true;
    }
    sl.unlock();

    // Update file info
    if (deleted)
    {
        remove_char(info, '\\');
        json::JSON info_json = json::JSON::Load_unsafe(info);
        long file_size = 0;
        if (type.compare(FILE_TYPE_PENDING) != 0)
        {
            file_size = info_json[FILE_SIZE].ToInt();
        }
        this->file_info_mutex.lock();
        this->file_info[type]["num"].AddNum(-1);
        this->file_info[type]["size"].AddNum(-file_size);
        this->file_info_mutex.unlock();
    }
}

/**
 * @description: Restore sealed file information
 * @param data -> All file information
 * @param data_size -> All file information size
 */
void EnclaveData::restore_file_info(const uint8_t *data, size_t data_size)
{
    // Restore file information
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    json::JSON sealed_files = json::JSON::Load_unsafe(data, data_size);
    if (sealed_files.size() <= 0)
    {
        return;
    }
    json::JSON file_spec = sealed_files[WL_FILE_SPEC_INFO];
    if (sealed_files.JSONType() != json::JSON::Class::Object)
    {
        p_log->err("Restore file info failed! Invalid json type, expected 'Object'");
        return;
    }
    sealed_files.ObjectRange().object->erase(WL_FILE_SPEC_INFO);
    for (auto it : *(sealed_files.ObjectRange().object))
    {
        if (it.second.JSONType() != json::JSON::Class::Array)
        {
            p_log->err("Restore file info failed! Invalid json type, expected 'Array'");
            return;
        }
        for (auto f_it : *(it.second.ArrayRange().object))
        {
            auto val = f_it.ObjectRange().begin();
            this->sealed_file[it.first][val->first] = val->second.ToString();
        }
    }
    sl.unlock();

    this->file_info_mutex.lock();
    this->file_info = file_spec;
    this->file_info_mutex.unlock();
}

/**
 * @description: Get sealed file item
 * @param cid -> File content id
 * @param info -> Reference to file item
 * @param raw -> Return raw data or a json
 * @return: File data
 */
std::string EnclaveData::get_file_info_item(std::string cid, std::string &info, bool raw)
{
    std::string ans;
    std::string data = info;
    remove_char(data, '\\');
    json::JSON data_json = json::JSON::Load_unsafe(data);

    if(data_json.hasKey(FILE_PENDING_STIME))
    {
        long stime = data_json[FILE_PENDING_STIME].ToInt();
        long etime = get_seconds_since_epoch();
        long utime = etime - stime;
        data = "{ \"" FILE_PENDING_DOWNLOAD_TIME "\" : \"" 
            + get_time_diff_humanreadable(utime) + "\" , "
            + "\"" FILE_PENDING_SIZE "\" : \""
            + get_file_size_humanreadable(this->get_pending_file_size(cid)) + "\""
            + " }";
    }

    if (raw)
    {
        return "\""+cid+"\" : " + data;
    }

    return "{ \""+cid+"\" : " + data + " }";
}

/**
 * @description: Get pending files' size
 * @param type -> File type
 * @return: Pending files' size
 */
size_t EnclaveData::get_files_size_by_type(const char *type)
{
    this->sealed_file_mutex.lock();
    std::map<std::string, std::string> tmp_files = this->sealed_file[type];
    this->sealed_file_mutex.unlock();

    size_t ans = 0;

    for (auto it : tmp_files)
    {
        ans += this->get_pending_file_size(it.first);
    }

    return ans;
}

/**
 * @description: Get sealed file information
 * @param cid -> IPFS content id
 * @return: Sealed file information
 */
std::string EnclaveData::get_file_info(std::string cid)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();
    std::string type;
    if (!find_file_type_nolock(cid, type))
    {
        return "";
    }

    json::JSON file = json::JSON::Load_unsafe(get_file_info_item(cid, this->sealed_file[type][cid], false));
    file[cid]["type"] = type;
    std::string file_str = file.dump();
    remove_char(file_str, '\\');

    return file_str;
}

/**
 * @description: Get all sealed file information
 * @return: All sealed file information
 */
std::string EnclaveData::get_file_info_all()
{
    this->sealed_file_mutex.lock();
    std::map<std::string, std::map<std::string, std::string>> tmp_sealed_file = this->sealed_file;
    this->sealed_file_mutex.unlock();

    std::string ans = "{";
    std::string pad = "  ";
    std::string tag;
    for (auto it = tmp_sealed_file.begin(); it != tmp_sealed_file.end(); it++)
    {
        std::string info = _get_file_info_by_type(it->first, pad + "  ", true);
        if (info.size() != 0)
        {
            ans += tag + "\n" + pad + "\"" + it->first + "\" : {\n" + info + "\n" + pad + "}";
            tag = ",";
        }
    }
    if (tag.compare(",") == 0)
    {
        ans += "\n";
    }
    ans += "}";

    return ans;
}

/**
 * @description: Get file info by type
 * @param type -> File type
 * @return: Result
 */
std::string EnclaveData::get_file_info_by_type(std::string type)
{
    return _get_file_info_by_type(type, "", false);
}

/**
 * @description: Get sealed file information by type
 * @param type -> File type
 * @param pad -> Space pad
 * @param raw -> Is raw data or not
 * @return: All sealed file information
 */
std::string EnclaveData::_get_file_info_by_type(std::string type, std::string pad, bool raw)
{
    this->sealed_file_mutex.lock();
    std::map<std::string, std::map<std::string, std::string>> tmp_sealed_file = this->sealed_file;
    this->sealed_file_mutex.unlock();

    std::string ans;
    std::string pad2;
    if (raw)
    {
        pad2 = pad;
    }
    else
    {
        ans = pad  + "{";
        pad2 = pad + "  ";
    }
    for (auto it = tmp_sealed_file[type].begin(); it != tmp_sealed_file[type].end(); it++)
    {
        if (!raw || (raw && it != tmp_sealed_file[type].begin()))
        {
            ans += "\n";
        }
        ans += pad2 + get_file_info_item(it->first, it->second, true);
        auto iit = it;
        iit++;
        if (iit != tmp_sealed_file[type].end())
        {
            ans += ",";
        }
        else if (!raw)
        {
            ans += "\n";
        }
    }
    if (!raw)
    {
        ans += pad + "}";
    }

    return ans;
}

/**
 * @description: Check if file is duplicated
 * @param cid -> IPFS content id
 * @param type -> Reference to file status type
 * @return: Duplicated or not
 */
bool EnclaveData::find_file_type_nolock(std::string cid, std::string &type)
{
    for (auto item : this->sealed_file)
    {
        if (item.second.find(cid) != item.second.end())
        {
            type = item.first;
            return true;
        }
    }

    return false;
}

/**
 * @description: Check if file is duplicated
 * @param cid -> IPFS content id
 * @param type -> Reference to file status type
 * @return: Duplicated or not
 */
bool EnclaveData::find_file_type(std::string cid, std::string &type)
{
    SafeLock sl(this->sealed_file_mutex);
    sl.lock();

    for (auto item : this->sealed_file)
    {
        if (item.second.find(cid) != item.second.end())
        {
            type = item.first;
            return true;
        }
    }

    return false;
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
    EnclaveData *ed = EnclaveData::get_instance();
    // Get srd info
    json::JSON wl_json;
    json::JSON srd_info = get_srd_info();
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
                srd_info[WL_SRD_DETAIL][uuid].ToInt(),
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
    std::string srd_spec;
    srd_spec.append("{\n")
            .append("\"" WL_SRD_COMPLETE "\" : ").append(std::to_string(srd_info[WL_SRD_COMPLETE].ToInt())).append(",\n")
            .append("\"" WL_SRD_REMAINING_TASK "\" : ").append(std::to_string(srd_info[WL_SRD_REMAINING_TASK].ToInt() + srd_task)).append(",\n")
            .append("\"" WL_DISK_AVAILABLE_FOR_SRD "\" : ").append(std::to_string(disk_avail_for_srd)).append(",\n")
            .append("\"" WL_DISK_AVAILABLE "\" : ").append(std::to_string(disk_avail)).append(",\n")
            .append("\"" WL_DISK_VOLUME "\" : ").append(std::to_string(disk_volume)).append(",\n")
            .append("\"" WL_SYS_DISK_AVAILABLE "\" : ").append(std::to_string(get_avail_space_under_dir_g(Config::get_instance()->base_path))).append(",\n")
            .append("\"" WL_SRD_DETAIL "\" : ").append(disk_info).append("\n")
            .append("}");
    wl_json[WL_SRD] = srd_spec;
    // Get file info
    this->file_info_mutex.lock();
    json::JSON file_info = this->file_info;
    this->file_info_mutex.unlock();
    json::JSON n_file_info;
    char buf[128];
    int space_num = 0;
    file_info[FILE_TYPE_PENDING]["size"].AddNum(this->get_files_size_by_type(FILE_TYPE_PENDING));
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
    return json::JSON::Load_unsafe(gen_workload_str(srd_task));
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
    if (uuid.size() > UUID_LENGTH * 2)
    {
        uuid = uuid.substr(0, UUID_LENGTH * 2);
    }
    uuid_disk_path_map_mutex.lock();
    this->uuid_to_disk_path[uuid] = path;
    this->disk_path_to_uuid[path] = uuid;
    uuid_disk_path_map_mutex.unlock();
}

/**
 * @description: Get uuid by disk path
 * @param path -> Disk path
 * @return: Disk uuid
 */
std::string EnclaveData::get_uuid(std::string path)
{
    SafeLock sl(uuid_disk_path_map_mutex);
    sl.lock();
    return this->disk_path_to_uuid[path];
}

/**
 * @description: Get disk path by uuid
 * @param uuid -> Disk uuid
 * @return: Disk path
 */
std::string EnclaveData::get_disk_path(std::string uuid)
{
    SafeLock sl(uuid_disk_path_map_mutex);
    sl.lock();
    return this->uuid_to_disk_path[uuid];
}

/**
 * @description: Check if related uuid is existed in given path
 * @param path -> Disk path
 * @return: Is the mapping existed by given disk path
 */
bool EnclaveData::is_disk_exist(std::string path)
{
    SafeLock sl(uuid_disk_path_map_mutex);
    sl.lock();
    return this->disk_path_to_uuid.find(path) != this->disk_path_to_uuid.end();
}

/**
 * @description: Check if related path is existed in given uuid
 * @param uuid -> Disk uuid
 * @return: Is the mapping existed by given uuid
 */
bool EnclaveData::is_uuid_exist(std::string uuid)
{
    SafeLock sl(uuid_disk_path_map_mutex);
    sl.lock();
    return this->uuid_to_disk_path.find(uuid) != this->uuid_to_disk_path.end();
}
