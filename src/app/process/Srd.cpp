#include "Srd.h"
#include "ECalls.h"

std::mutex srd_info_mutex;
crust::Log *p_log = crust::Log::get_instance();
extern sgx_enclave_id_t global_eid;

/**
 * @description: Compare disk available space
 * @param j1 -> disk 1
 * @param j2 -> disk 2
 * @return: Decrease order sort
 * */
static bool cmp_available(json::JSON j1, json::JSON j2)
{
    return j1["available"].ToInt() < j2["available"].ToInt();
}

/**
 * @description: If the given paths have same disk, just choose one of the same
 * @param srd_paths -> Input srd paths
 * @return: Final chosen srd paths
 * */
json::JSON get_valid_srd_path(json::JSON srd_paths)
{
    json::JSON ans;

    // Get disk info
    std::unordered_set<std::string> fsid_s;
    for (int i = 0; i < srd_paths.size(); i++)
    {
        std::string path = srd_paths[i].ToString();

        // Create path
        create_directory(path);

        struct statfs disk_info;
        if (statfs(path.c_str(), &disk_info) == -1)
        {
            return ans;
        }
        char *p_fsid = hexstring_safe(&disk_info.f_fsid, sizeof(disk_info.f_fsid));
        std::string fsid_str(p_fsid, sizeof(disk_info.f_fsid));
        if (p_fsid != NULL)
        {
            free(p_fsid);
        }
        if (fsid_s.find(fsid_str) == fsid_s.end())
        {
            ans.append(path);
            fsid_s.insert(fsid_str);
        }
    }

    return ans;
}

/**
 * @description: Get srd disks info according to configure
 * @param true_srd_capacity -> True assigned size
 * @return: A path to assigned size map
 * */
json::JSON get_increase_srd_info(size_t &true_srd_capacity)
{
    // Get multi-disk info
    Config *p_config = Config::get_instance();
    json::JSON disk_info_json;
    size_t total_avail = 0;
    if (p_config->srd_paths.size() != 0)
    {
        json::JSON srd_paths = get_valid_srd_path(p_config->srd_paths);
        for (int i = 0; i < srd_paths.size(); i++)
        {
            std::string path = srd_paths[i].ToString();
            // Calculate free disk
            disk_info_json[path]["available"] = get_avail_space_under_dir_g(path);
            if (disk_info_json[path]["available"].ToInt() <= SRD_RESERVED_SPACE)
            {
                disk_info_json[path]["available"] = 0;
            }
            else
            {
                disk_info_json[path]["available"] = disk_info_json[path]["available"].ToInt() - SRD_RESERVED_SPACE;
            }
            total_avail += disk_info_json[path]["available"].ToInt();
        }
    }
    else
    {
        // Create path
        create_directory(p_config->empty_path);
        // Calculate free disk
        disk_info_json[p_config->empty_path]["available"] = get_avail_space_under_dir_g(p_config->empty_path);
        if (disk_info_json[p_config->empty_path]["available"].ToInt() <= SRD_RESERVED_SPACE)
        {
            disk_info_json[p_config->empty_path]["available"] = 0;
        }
        else
        {
            disk_info_json[p_config->empty_path]["available"] = disk_info_json[p_config->empty_path]["available"].ToInt() - SRD_RESERVED_SPACE;
        }
        total_avail = disk_info_json[p_config->empty_path]["available"].ToInt();
    }
    true_srd_capacity = std::min(total_avail, true_srd_capacity);

    // Assigned srd space to disk
    size_t increase_size = 0;
    auto disk_range = disk_info_json.ObjectRange();
    for (auto it = disk_range.begin(); it != disk_range.end(); it++)
    {
        std::string path = it->first;
        // According to the available space to assign increased size
        // Larger the available space is, larger the increased size is. 
        double cur_increase_size = (double)(it->second["available"].ToInt()) / (double)total_avail * (double)true_srd_capacity;
        // If assigned size larger than true_srd_capacity
        if (increase_size + cur_increase_size > true_srd_capacity)
        {
            cur_increase_size = true_srd_capacity - increase_size;
        }
        // Judge if assigned size larger than current disk available space
        if (cur_increase_size > it->second["available"].ToInt())
        {
            it->second["increased"] = it->second["available"].ToInt();
        }
        else
        {
            it->second["increased"] = (long)cur_increase_size;
            if (cur_increase_size - (double)(it->second["increased"].ToInt()) > 0.0)
            {
                if (increase_size + cur_increase_size < true_srd_capacity
                        && it->second["available"].ToInt() > it->second["increased"].ToInt())
                {
                    it->second["increased"] = it->second["increased"].ToInt() + 1;
                }
            }
        }
        increase_size += it->second["increased"].ToInt();

        if (increase_size >= true_srd_capacity)
        {
            break;
        }
    }

    return disk_info_json;
}

/**
 * @description: Decrease srd space
 * @param true_srd_capacity -> True decreased size
 * @return: Path to decrease size map
 * */
json::JSON get_decrease_srd_info(size_t &true_srd_capacity)
{
    crust::DataBase *db = crust::DataBase::get_instance();
    std::string disk_info_str;

    srd_info_mutex.lock();
    db->get("srd_info", disk_info_str);
    srd_info_mutex.unlock();

    json::JSON disk_info_json = json::JSON::Load(disk_info_str);
    json::JSON ans;
    std::vector<json::JSON> disk_info_v;

    // Calculate available and assigned size
    size_t total_avail = 0;
    size_t total_assigned = 0;
    auto disk_range = disk_info_json.ObjectRange();
    for (auto it = disk_range.begin(); it != disk_range.end(); it++)
    {
        if (!it->second.hasKey("assigned") || it->second["assigned"].ToInt() == 0)
        {
            continue;
        }
        json::JSON tmp;
        tmp["path"] = it->first;
        tmp["available"] = get_avail_space_under_dir_g(it->first);
        tmp["assigned"] = it->second["assigned"];
        disk_info_v.push_back(tmp);

        total_avail += tmp["available"].ToInt();
        total_assigned += tmp["assigned"].ToInt();
    }
    true_srd_capacity = std::min(total_assigned, true_srd_capacity);

    std::sort(disk_info_v.begin(), disk_info_v.end(), cmp_available);
    size_t decrease_size = 0;
    for (int i = 0, j = disk_info_v.size() - 1; i < (int)disk_info_v.size() && j >= 0; i++, j--)
    {
        std::string path = disk_info_v[i]["path"].ToString();
        // According to the available space to assign decreased size
        // Smaller the available space is, larger the decreased size is. 
        double cur_decrease_size = (double)(disk_info_v[j]["available"].ToInt()) / (double)total_avail * (double)true_srd_capacity;
        // If decreased size larger than true_srd_capacity, set true decrease size to the left
        if (decrease_size + cur_decrease_size > true_srd_capacity)
        {
            cur_decrease_size = true_srd_capacity - decrease_size;
        }
        // Judge if decreased size larger than current disk assigned size
        if (cur_decrease_size > disk_info_v[i]["assigned"].ToInt())
        {
            // If larger, set decrease_size to assigned size
            ans[path]["decreased"] = disk_info_v[i]["assigned"];
        }
        else
        {
            // If smaller, set decrease_size according to situation
            ans[path]["decreased"] = (long)cur_decrease_size;
            if (cur_decrease_size - (double)(ans[path]["decreased"].ToInt()) > 0.0)
            {
                if (decrease_size + cur_decrease_size < true_srd_capacity
                        && disk_info_v[i]["assigned"].ToInt() > ans[path]["decreased"].ToInt())
                {
                    ans[path]["decreased"] = ans[path]["decreased"].ToInt() + 1;
                }
            }
        }
        decrease_size += ans[path]["decreased"].ToInt();

        if (decrease_size + cur_decrease_size >= true_srd_capacity)
        {
            break;
        }
    }

    return ans;
}

/**
 * @description: Change SRD space
 * @param change -> SRD space number
 * */
void srd_change(long change)
{
    Config *p_config = Config::get_instance();

    if (change > 0)
    {
        size_t true_increase = change;
        json::JSON disk_info_json = get_increase_srd_info(true_increase);
        // Print disk info
        auto disk_range = disk_info_json.ObjectRange();
        for (auto it = disk_range.begin(); it != disk_range.end(); it++)
        {
            p_log->info("Available space is %luG disk in '%s'\n", 
                    it->second["available"].ToInt(), it->first.c_str());
        }
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);
        std::vector<std::string> srd_paths;
        for (auto it = disk_range.begin(); it != disk_range.end(); it++)
        {
            for (int i = 0; i < it->second["increased"].ToInt(); i++)
            {
                srd_paths.push_back(it->first);
            }
        }
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        #pragma omp parallel for num_threads(p_config->srd_thread_num)
        for (size_t i = 0; i < srd_paths.size(); i++)
        {
            std::string path = srd_paths[i];
            Ecall_srd_increase(global_eid, path.c_str());
        }

        p_config->change_empty_capacity(true_increase);
        p_log->info("Increase %dG srd files success, the srd workload will change gradually in next validation loops\n", true_increase);
    }
    else if (change < 0)
    {
        size_t true_decrease = -change;
        size_t ret_size = 0;
        size_t total_decrease_size = 0;
        json::JSON disk_decrease = get_decrease_srd_info(true_decrease);
        p_log->info("True decreased space is:%d\n", true_decrease);
        Ecall_srd_decrease(global_eid, &ret_size, true_decrease);
        total_decrease_size = ret_size;
        p_config->change_empty_capacity(total_decrease_size);
        p_log->info("Decrease %luG srd files success, the srd workload will change in next validation loop\n", total_decrease_size);
    }
}

/**
 * @description: Check if disk's available space is smaller than minimal reserved space,
 * if it is, delete srd space
 * */
void *srd_check_reserved(void *)
{
    crust::DataBase *db = crust::DataBase::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    std::string srd_info_str;

    while (true)
    {
        // Lock srd_info
        srd_info_mutex.lock();
        if (CRUST_SUCCESS != (crust_status = db->get("srd_info", srd_info_str)))
        {
            p_log->debug("Get srd info failed! Error code:%lx\n", crust_status);
            // Unlock srd_info
            srd_info_mutex.unlock();
            sleep(15);
            continue;
        }
        json::JSON srd_info_json = json::JSON::Load(srd_info_str);
        json::JSON del_info_json;
        auto p_obj = srd_info_json.ObjectRange();
        bool is_changed = false;
        for (auto sit = p_obj.begin(); sit != p_obj.end(); sit++)
        {
            size_t avail_space = get_avail_space_under_dir_g(sit->first);
            long del_space = 0;
            if (avail_space < SRD_RESERVED_SPACE)
            {
                is_changed = true;
                del_space = SRD_RESERVED_SPACE - avail_space;
                if (del_space > sit->second["assigned"].ToInt())
                {
                    del_space = sit->second["assigned"].ToInt();
                }
                del_info_json[sit->first] = del_space;
            }
        }
        // Unlock srd_info
        srd_info_mutex.unlock();

        // Do update
        if (is_changed)
        {
            // Update srd metadata
            std::string del_info_str = del_info_json.dump();
            if (SGX_SUCCESS != Ecall_srd_update_metadata(global_eid, del_info_str.c_str(), del_info_str.size()))
            {
                p_log->err("Invoke srd metadata failed! Error code:%lx\n", sgx_status);
            }
        }

        sleep(15);
    }
    return NULL;
}
