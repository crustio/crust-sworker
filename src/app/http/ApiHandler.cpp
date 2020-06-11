#include "ApiHandler.h"
#include "sgx_tseal.h"
#include "tbb/concurrent_unordered_map.h"
#include <exception>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


extern sgx_enclave_id_t global_eid;
extern tbb::concurrent_unordered_map<std::string, std::string> sealed_tree_map;

crust::Log *p_log = crust::Log::get_instance();

// Append an HTTP rel-path to a local filesystem path.
// The returned path is normalized for the platform.
std::string path_cat(beast::string_view base, beast::string_view path)
{
    if(base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for(auto& c : result)
        if(c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}

/**
 * @description: Get url parameters
 * @param url -> Request URL
 * @return: Key value pair url parameters
 * */
std::map<std::string, std::string> get_params(std::string &url)
{
    std::map<std::string, std::string> ans;
    size_t spos = url.find('\?');
    size_t epos;
    if (spos == std::string::npos)
    {
        return ans;
    }
    spos++;
    while (spos < url.size())
    {
        epos = url.find('&', spos);
        if (epos == std::string::npos)
        {
            epos = url.size();
        }
        size_t ppos = url.find('=', spos);
        if (ppos > epos || ppos == std::string::npos)
        {
            return ans;
        }
        std::string key = url.substr(spos, ppos - spos);
        ppos++;
        std::string val = url.substr(ppos, epos - ppos);
        ans[key] = val;

        spos = epos + 1;
    }

    return ans;
}

/**
 * @description: Handle websocket request
 * @param path -> Request path
 * @param data -> Request data
 * @param close_connection -> Indicate whether to close connection
 * @return: Response data as json format
 * */
std::string ApiHandler::websocket_handler(std::string &path, std::string &data, bool &close_connection)
{
    Config *p_config = Config::get_instance();
    json::JSON res;
    UrlEndPoint *url_end_point = get_url_end_point(p_config->api_base_url);
    res["status"] = 400;
    res["body"] = "Unknown request!";

    // Storage seal file block
    std::string cur_path = url_end_point->base + "/storage/seal";
    if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
    {
        res["status"] = 500;
        std::string error_info;
        crust_status_t crust_status = CRUST_SUCCESS;
        sgx_status_t sgx_status = SGX_SUCCESS;

        p_log->info("Dealing with seal request...\n");

        // Parse paramters
        json::JSON req_json;
        try
        {
            req_json = json::JSON::Load(data);
        }
        catch (std::exception e)
        {
            error_info.append("Validate MerkleTree failed! Parse json failed! Error: ").append(e.what());
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
            res["status"] = 400;
            goto cleanup;
        }
        json::JSON tree_json = req_json["body"];
        std::string backup = req_json["backup"].ToString();
        std::string dir_path = req_json["path"].ToString();
        this->block_left_num = this->block_num = req_json["block_num"].ToInt();
        remove_char(backup, '\\');

        // Get backup info
        if (p_config->chain_backup.compare(backup) != 0)
        {
            error_info = "Validate MerkleTree failed!Error: Invalid backup!";
            res["status"] = 401;
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
            goto cleanup;
        }
        // Check if body is validated
        if (tree_json.size() == 0 || tree_json.size() == -1)
        {
            error_info = "Validate MerkleTree failed!Error: Empty body!";
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
            res["status"] = 402;
            goto cleanup;
        }

        // ----- Seal file ----- //
        std::string content;
        std::string org_root_hash_str = tree_json["hash"].ToString();
        char *p_new_path = (char*)malloc(dir_path.size());
        memset(p_new_path, 0, dir_path.size());
        std::string org_tree_str = tree_json.dump();
        remove_char(org_tree_str, '\\');
        remove_char(org_tree_str, '\n');
        remove_char(org_tree_str, ' ');
        sgx_status = Ecall_seal_file(global_eid, &crust_status, org_tree_str.c_str(), org_tree_str.size(),
                dir_path.c_str(), p_new_path, dir_path.size());

        if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_SEAL_DATA_FAILED:
                    error_info = "Internal error: seal data failed!";
                    break;
                case CRUST_STORAGE_FILE_NOTFOUND:
                    error_info = "Given file cannot be found!";
                    break;
                default:
                    error_info = "Unexpected error!";
                }
            }
            else
            {
                error_info = "Invoke SGX api failed!";
            }
            p_log->err("Seal data failed!Error code:%lx(%s)\n", crust_status, error_info.c_str());
            res["body"] = error_info;
            res["status"] = 403;
            goto cleanup;
        }
        p_log->info("Seal file successfully!\n");

        std::string new_tree_str = sealed_tree_map[org_root_hash_str];
        remove_char(new_tree_str, ' ');
        remove_char(new_tree_str, '\n');
        remove_char(new_tree_str, '\\');
        res["body"] = new_tree_str;
        res["path"] = std::string(p_new_path, dir_path.size());
        res["status"] = 200;
        sealed_tree_map.unsafe_erase(org_root_hash_str);

        close_connection = true;

        goto cleanup;
    }


    // Storage unseal file block
    cur_path = url_end_point->base + "/storage/unseal";
    if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
    {
        res["status"] = 500;
        std::string error_info;

        p_log->info("Dealing with unseal request...\n");

        // Parse parameters
        json::JSON req_json;
        try
        {
            req_json = json::JSON::Load(data);
        }
        catch (std::exception e)
        {
            error_info.append("Unseal file failed! Parse json failed! Error: ").append(e.what());
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
            res["status"] = 400;
            goto cleanup;
        }

        std::string dir_path = req_json["path"].ToString();
        std::string backup = req_json["backup"].ToString();

        // Check backup
        remove_char(backup, '\\');
        if (p_config->chain_backup.compare(backup) != 0)
        {
            error_info = "Unseal data failed!Invalid backup!";
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
            res["status"] = 401;
            goto cleanup;
        }

        // Get sub files' path
        std::vector<std::string> files_str = get_sub_folders_and_files(dir_path.c_str());
        std::vector<const char *> sub_files;
        for (size_t i = 0; i < files_str.size(); i++)
        {
            sub_files.push_back(files_str[i].c_str());
        }
        if (sub_files.size() == 0)
        {
            error_info = "Empty data directory!";
            p_log->err("%s\n", error_info.c_str());
            res["status"] = 402;
            res["body"] = error_info;
            goto cleanup;
        }

        // Unseal file
        crust_status_t crust_status = CRUST_SUCCESS;
        char *p_new_path = (char*)malloc(dir_path.size());
        memset(p_new_path, 0, dir_path.size());
        sgx_status_t sgx_status = Ecall_unseal_file(global_eid, &crust_status,
                const_cast<char**>(sub_files.data()), sub_files.size(), dir_path.c_str(), p_new_path, dir_path.size());

        if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_UNSEAL_DATA_FAILED:
                    error_info = "Internal error: unseal data failed!";
                    break;
                case CRUST_STORAGE_UPDATE_FILE_FAILED:
                    error_info = "Update new file failed!";
                    break;
                case CRUST_STORAGE_FILE_NOTFOUND:
                    error_info = "Given file cannot be found!";
                    break;
                default:
                    error_info = "Unexpected error!";
                }
            }
            else
            {
                error_info = "Invoke SGX api failed!";
            }
            p_log->err("Unseal data failed!Error code:%lx(%s)\n", crust_status, error_info.c_str());
            res["body"] = error_info;
            res["status"] = 403;
        }
        else
        {
            p_log->info("Unseal data successfully!\n");
            res["body"] = "Unseal data successfully!";
            res["path"] = std::string(p_new_path, dir_path.size());
            res["status"] = 200;
        }

        free(p_new_path);

        close_connection = true;

        goto cleanup;
    }

cleanup:

    if (res["status"].ToInt() >= 300)
    {
        close_connection = true;
    }

    return res.dump();
}

void *ApiHandler::change_empty(void *)
{
    Config *p_config = Config::get_instance();
    crust::DataBase *db = crust::DataBase::get_instance();
    int change = change_empty_num;

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
        p_log->info("Start sealing %luG empty files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);
        std::vector<std::string> srd_paths;
        for (auto it = disk_range.begin(); it != disk_range.end(); it++)
        {
            for (int i = 0; i < it->second["increased"].ToInt(); i++)
            {
                srd_paths.push_back(it->first);
            }
        }
        // Use omp parallel to seal empty disk, the number of threads is equal to the number of CPU cores
        tbb::concurrent_unordered_map<std::string, size_t> cal_m;
        #pragma omp parallel for num_threads(p_config->srd_thread_num)
        for (size_t i = 0; i < srd_paths.size(); i++)
        {
            std::string path = srd_paths[i];
            Ecall_srd_increase_empty(global_eid, path.c_str());
            cal_m[path] += 1;
        }
        json::JSON assigned_srd_json;
        for (auto it : cal_m)
        {
            assigned_srd_json[it.first] = it.second;
        }
        db->set("srd_info", assigned_srd_json.dump());

        p_config->change_empty_capacity(true_increase);
        p_log->info("Increase %dG empty files success, the empty workload will change gradually in next validation loops\n", true_increase);
    }
    else if (change < 0)
    {
        size_t true_decrease = -change;
        size_t ret_size = 0;
        size_t total_decrease_size = 0;
        json::JSON disk_decrease = get_decrease_srd_info(true_decrease);
        p_log->info("True decreased space is:%d\n", true_decrease);
        for (auto it : disk_decrease.ObjectRange())
        {
            Ecall_srd_decrease_empty(global_eid, &ret_size, it.first.c_str(), (size_t)it.second["decreased"].ToInt());
            total_decrease_size += ret_size;
        }
        p_config->change_empty_capacity(total_decrease_size);
        p_log->info("Decrease %luG empty files success, the empty workload will change in next validation loop\n", total_decrease_size);
    }

    change_empty_mutex.lock();
    in_changing_empty = false;
    change_empty_mutex.unlock();

    return NULL;
}
