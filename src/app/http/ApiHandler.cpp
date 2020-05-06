#include "ApiHandler.h"
#include "sgx_tseal.h"

#include <exception>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


extern sgx_enclave_id_t global_eid;
extern std::map<std::string, std::string> sealed_tree_map;

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

    // Storage seal file block
    std::string cur_path = url_end_point->base + "/storage/seal";
    if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
    {
        res["status"] = 200;
        std::string error_info;
        crust_status_t crust_status = CRUST_SUCCESS;
        sgx_status_t sgx_status = SGX_SUCCESS;

        p_log->info("Dealing with seal request...\n");

        // ----- Validate MerkleTree ----- //
        json::JSON req_json;
        try
        {
            req_json = json::JSON::Load(data);
        }
        catch (std::exception e)
        {
            p_log->err("Parse json failed!Error: %s\n", e.what());
            res["body"] = "Validate MerkleTree failed!Error invalide MerkleTree json!";
            res["status"] = 400;
            goto cleanup;
        }
        json::JSON body_json = req_json["body"];
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
        if (body_json.size() == 0)
        {
            error_info = "Validate MerkleTree failed!Error: Empty body!";
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
            res["status"] = 402;
            goto cleanup;
        }

        // Get MerkleTree
        MerkleTree *root = deserialize_merkle_tree_from_json(body_json);
        if (root == NULL)
        {
            p_log->err("Deserialize MerkleTree failed!\n");
            res["body"] = "Deserialize MerkleTree failed!";
            res["status"] = 403;
            goto cleanup;
        }

        // Validate MerkleTree
        if (SGX_SUCCESS != ecall_validate_merkle_tree(global_eid, &crust_status, &root) ||
            (CRUST_SUCCESS != crust_status && CRUST_MERKLETREE_DUPLICATED != crust_status))
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_INVALID_MERKLETREE:
                    error_info = "Invalid MerkleTree structure!";
                    break;
                default:
                    error_info = "Undefined error!";
                }
            }
            else
            {
                error_info = "Invoke SGX api failed!";
            }
            p_log->err("Validate merkle tree failed!Error code:%lx(%s)\n",
                       crust_status, error_info.c_str());
            res["body"] = error_info;
            res["status"] = 404;
        }
        else
        {
            if (CRUST_MERKLETREE_DUPLICATED == crust_status)
            {
                res["status"] = 201;
                res["body"] = "MerkleTree has been validated!";
            }
            else
            {
                p_log->info("Validate merkle tree successfully!\n");
            }
            seal_check_validate = true;
        }


        // ----- Seal file ----- //
        std::string content;
        std::string org_root_hash_str(root->hash, HASH_LENGTH * 2);
        sgx_status = ecall_seal_file(global_eid, &crust_status, &root, 
                dir_path.c_str(), dir_path.size());
    
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
            p_log->info("Seal data failed!Error code:%lx(%s)\n", crust_status, error_info.c_str());
            res["body"] = error_info;
            res["status"] = 405;
            goto cleanup;
        }
        p_log->info("Seal file successfully!\n");

        std::string tree_str = sealed_tree_map[org_root_hash_str];
        remove_char(tree_str, ' ');
        remove_char(tree_str, '\n');
        remove_char(tree_str, '\\');
        res["body"] = tree_str;
        sealed_tree_map.erase(org_root_hash_str);

        goto cleanup;
    }


    // Storage unseal file block
    cur_path = url_end_point->base + "/storage/unseal";
    if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
    {
        res["status"] = 200;
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
        sgx_status_t sgx_status = ecall_unseal_file(global_eid, &crust_status,
                const_cast<char**>(sub_files.data()), sub_files.size(), dir_path.c_str());

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
        }

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
    int change = change_empty_num;

    if (change > 0)
    {
        // Increase empty
        size_t free_space = get_free_space_under_directory(p_config->empty_path) / 1024;
        p_log->info("Free space is %luG disk in '%s'\n", free_space, p_config->empty_path.c_str());
        size_t true_change = free_space <= 10 ? 0 : std::min(free_space - 10, (size_t)change);
        p_log->info("Start sealing %dG disk (thread number: %d) ...\n", true_change, p_config->srd_thread_num);
// Use omp parallel to seal empty files, the number of threads is equal to the number of CPU cores
#pragma omp parallel for num_threads(p_config->srd_thread_num)
        for (size_t i = 0; i < (size_t)true_change; i++)
        {
            ecall_srd_increase_empty(global_eid, p_config->empty_path.c_str());
        }

        p_config->change_empty_capacity(true_change);
        p_log->info("Increase %dG empty files success, the empty workload will change gradually in next validation loops\n", true_change);
    }
    else if (change < 0)
    {
        change = -change;
        size_t true_decrease = 0;
        ecall_srd_decrease_empty(global_eid, &true_decrease, p_config->empty_path.c_str(), (size_t)change);
        p_config->change_empty_capacity(-change);
        p_log->info("Decrease %luG empty files success, the empty workload will change in next validation loop\n", true_decrease);
    }

    change_empty_mutex.lock();
    in_changing_empty = false;
    change_empty_mutex.unlock();

    return NULL;
}

void ApiHandler::set_root_hash(uint8_t *root_hash, size_t hash_len)
{
    if (root_hash == NULL)
        return;

    this->root_hash_v = std::vector<uint8_t>(root_hash, root_hash + hash_len);
}

void ApiHandler::set_root_hash(std::string root_hash_str)
{
    uint8_t *root_hash_u = hex_string_to_bytes(root_hash_str.c_str(), root_hash_str.size());
    if (root_hash_u == NULL)
    {
        return;
    }

    this->root_hash_v = std::vector<uint8_t>(root_hash_u, root_hash_u + root_hash_str.size() / 2);
}
