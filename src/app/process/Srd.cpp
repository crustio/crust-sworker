#include "Srd.h"
#include "ECalls.h"
#include "Ctpl.h"
#include "HttpClient.h"

crust::Log *p_log = crust::Log::get_instance();

size_t g_srd_reserved_space = 50;
std::mutex srd_info_mutex;

extern sgx_enclave_id_t global_eid;

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
    long srd_reserved_space = get_reserved_space();
    if (p_config->srd_paths.size() != 0)
    {
        json::JSON srd_paths = get_valid_srd_path(p_config->srd_paths);
        for (int i = 0; i < srd_paths.size(); i++)
        {
            std::string path = srd_paths[i].ToString();
            // Calculate free disk
            disk_info_json[path]["available"] = get_avail_space_under_dir_g(path);
            if (disk_info_json[path]["available"].ToInt() <= srd_reserved_space)
            {
                disk_info_json[path]["available"] = 0;
            }
            else
            {
                disk_info_json[path]["available"] = disk_info_json[path]["available"].ToInt() - srd_reserved_space;
            }
            total_avail += disk_info_json[path]["available"].ToInt();
            disk_info_json[path]["left"] = disk_info_json[path]["available"].ToInt();
        }
    }
    else
    {
        // Create path
        create_directory(p_config->empty_path);
        // Calculate free disk
        disk_info_json[p_config->empty_path]["available"] = get_avail_space_under_dir_g(p_config->empty_path);
        if (disk_info_json[p_config->empty_path]["available"].ToInt() <= srd_reserved_space)
        {
            disk_info_json[p_config->empty_path]["available"] = 0;
        }
        else
        {
            disk_info_json[p_config->empty_path]["available"] = disk_info_json[p_config->empty_path]["available"].ToInt() - srd_reserved_space;
        }
        total_avail = disk_info_json[p_config->empty_path]["available"].ToInt();
        disk_info_json[p_config->empty_path]["left"] = disk_info_json[p_config->empty_path]["available"].ToInt();
    }
    true_srd_capacity = std::min(total_avail, true_srd_capacity);

    // Assigned srd space to disk
    size_t increase_acc = true_srd_capacity;
    auto disk_range = disk_info_json.ObjectRange();
    for (auto it = disk_range.begin(); increase_acc > 0; )
    {
        std::string path = it->first;
        if (it->second["left"].ToInt() > 0)
        {
            it->second["increased"] = it->second["increased"].ToInt() + 1;
            it->second["left"] = it->second["left"].ToInt() - 1;
            increase_acc--;
        }
        if (++it == disk_range.end())
        {
            it = disk_range.begin();
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

    // Get decreased info
    size_t decrease_size = true_srd_capacity;
    for (auto it = disk_info_v.begin(); decrease_size > 0; )
    {
        std::string path = (*it)["path"].ToString();
        if ((*it)["assigned"].ToInt() > 0)
        {
            ans[path]["decreased"] = ans[path]["decreased"].ToInt() + 1;
            (*it)["assigned"] = (*it)["assigned"].ToInt() - 1;
            decrease_size--;
        }
        if (++it == disk_info_v.end())
        {
            it = disk_info_v.begin();
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
        // Add left change to next srd, if have
        if (change > (long)true_increase)
        {
            long left_srd_num = change - true_increase;
            Ecall_srd_set_change(global_eid, left_srd_num);
            p_log->info("%ldG srd task left, add it to next srd.\n", left_srd_num);
        }
        if (true_increase == 0)
        {
            p_log->warn("No available space for srd!\n");
            return;
        }
        // Print disk info
        auto disk_range = disk_info_json.ObjectRange();
        for (auto it = disk_range.begin(); it != disk_range.end(); it++)
        {
            p_log->info("Available space is %ldG disk in '%s', will use %ldG space\n", 
                    it->second["available"].ToInt(),
                    it->first.c_str(),
                    it->second["increased"].ToInt());
        }
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);
        size_t increase_acc = true_increase;
        std::vector<std::string> srd_paths;
        for (auto it = disk_range.begin(); increase_acc > 0; )
        {
            if (it->second["increased"].ToInt() > 0)
            {
                srd_paths.push_back(it->first);
                it->second["increased"] = it->second["increased"].ToInt() - 1;
                increase_acc--;
            }
            if (++it == disk_range.end())
            {
                it = disk_range.begin();
            }
        }

        // ----- Do srd ----- //
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        ctpl::thread_pool pool(p_config->srd_thread_num);
        std::vector<std::shared_ptr<std::future<void>>> tasks_v;
        for (size_t i = 0; i < srd_paths.size(); i++)
        {
            std::string path = srd_paths[i];
            sgx_enclave_id_t eid = global_eid;
            tasks_v.push_back(std::make_shared<std::future<void>>(pool.push([eid, path](int /*id*/){
                if (SGX_SUCCESS != Ecall_srd_increase(eid, path.c_str()))
                {
                    // If failed, add current task to next turn
                    Ecall_srd_set_change(global_eid, 1);
                }
            })));
        }
        // Wait for srd task
        for (auto it : tasks_v)
        {
            try 
            {
                it.get();
            }
            catch (std::exception &e)
            {
                p_log->err("Catch exception:");
                std::cout << e.what() << std::endl;
            }
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
        if (true_decrease == 0)
        {
            p_log->warn("No srd space to delete!\n");
            return;
        }
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
void srd_check_reserved(void)
{
    crust::DataBase *db = crust::DataBase::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    std::string srd_info_str;
    long srd_reserved_space = get_reserved_space();

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
            if ((long)avail_space < srd_reserved_space)
            {
                is_changed = true;
                del_space = srd_reserved_space - avail_space;
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
}

/**
 * @description: Get reserved space
 * @return: srd reserved space
 * */
size_t get_reserved_space()
{
    return g_srd_reserved_space;
}

/**
 * @description: Set reserved space
 * @param reserved -> Reserved space
 * */
void set_reserved_space(size_t reserved)
{
    g_srd_reserved_space = reserved;
}

/**
 * @description: Get old TEE's reserved space from url
 * @param url -> Indicates old TEE url
 * @return: Old TEE srd reserved space
 * */
long get_old_reserved_space(std::string url)
{
    long srd_reserved_space = 0;
    HttpClient *client = new HttpClient();
    http::response<http::string_body> res = client->Get(url);
    json::JSON res_json = json::JSON::Load(res.body());
    if (!res_json.hasKey("srd_reserved_space"))
    {
        srd_reserved_space = -1;
    }
    else
    {
        srd_reserved_space = res_json["srd_reserved_space"].ToInt();
    }

    delete client;

    return srd_reserved_space;
}
