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
    res["status"] = 400;
    res["body"] = "Unknown request!";

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
            error_info.append("Validate MerkleTree failed! Parse json failed! Error: ").append(e.what());
            p_log->err("%s\n", error_info.c_str());
            res["body"] = error_info;
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
            goto cleanup;
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
        char *p_new_path = (char*)malloc(dir_path.size());
        memset(p_new_path, 0, dir_path.size());
        sgx_status = ecall_seal_file(global_eid, &crust_status, &root, 
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
        res["path"] = std::string(p_new_path, dir_path.size());
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
        char *p_new_path = (char*)malloc(dir_path.size());
        memset(p_new_path, 0, dir_path.size());
        sgx_status_t sgx_status = ecall_unseal_file(global_eid, &crust_status,
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
        }

        free(p_new_path);

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

// TODO: Should limit thread number in enclave
/**
 * @desination: Start rest service
 * @return: Start status
 * */
//template<class Body, class Allocator, class Send>
//void ApiHandler::http_handler(beast::string_view /*doc_root*/,
//    http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, bool is_ssl)
/*
void ApiHandler::http_handler(beast::string_view doc_root,
    http::request<http::basic_fields<http::string_body>>&& req, Queue&& send, bool is_ssl)
{
    Config *p_config = Config::get_instance();
    crust::Log *p_log = crust::Log::get_instance();
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);
    std::string cur_path;

    // Returns a bad request response
    auto const bad_request =
    [&req](beast::string_view why)
    {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Make sure we can handle the method
    if( req.method() != http::verb::get &&
        req.method() != http::verb::post &&
        req.method() != http::verb::head)
        return send(bad_request("Unknown HTTP-method"));

    // Request path must be absolute and not contain "..".
    if( req.target().empty() ||
        req.target()[0] != '/' ||
        req.target().find("..") != beast::string_view::npos)
        return send(bad_request("Illegal request-target"));

    // Build the path to the requested file
    std::string path = std::string(req.target().data(), req.target().size());
    p_log->debug("Request url:%s\n", path.c_str());
    std::map<std::string, std::string> params = get_params(path);
    size_t epos = path.find('\?');
    if (epos != std::string::npos)
    {
        path = path.substr(0, epos);
    }


    // Respond to HEAD request
    if(req.method() == http::verb::head)
    {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }


    // Respond to GET request
    if(req.method() == http::verb::get)
    {
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("crust return"),
            std::make_tuple(http::status::ok, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");


        // Outter APIs
        cur_path = urlendpoint->base + "/status";
        if (path.compare(cur_path) == 0)
        {
            validation_status_t validation_status = VALIDATE_STOP;

            if (ecall_return_validation_status(global_eid, &validation_status) != SGX_SUCCESS)
            {
                p_log->err("Get validation status failed.\n");
                res.body() = "InternalError";
                goto getcleanup;
            }

            res.body() = std::string("{\"validation_status\":") + "\"" + validation_status_strings[validation_status] + "\"}";
            goto getcleanup;
        }

        cur_path = urlendpoint->base + "/report";
        if (path.compare(cur_path) == 0)
        {
            // ----- Call ecall function to get work report ----- //
            size_t report_len = 0;
            crust_status_t crust_status = CRUST_SUCCESS;
            if (ecall_generate_work_report(global_eid, &crust_status, &report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
            {
                p_log->err("Generate validation report failed. Error code: %x\n", crust_status);
                res.body() = "InternalError";
                goto getcleanup;
            }

            char *report = new char[report_len];
            if (ecall_get_work_report(global_eid, &crust_status, report, report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
            {
                p_log->err("Get validation report failed.\n");
                res.body() = "InternalError";
                goto getcleanup;
            }

            if (report == NULL)
            {
                res.body() = "InternalError";
                goto getcleanup;
            }

            res.body() = report;
            goto getcleanup;
        }


    getcleanup:

        res.content_length(res.body().size());
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }


    // Respond to POST request
    if(req.method() == http::verb::post)
    {
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("crust return"),
            std::make_tuple(http::status::ok, req.version())};
        // Entry network process
        cur_path = urlendpoint->base + "/entry/network";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            sgx_status_t status_ret = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            int version = IAS_API_DEF_VERSION;
            p_log->info("Processing entry network application...\n");
            uint32_t qsz;
            size_t dqsz = 0;
            sgx_quote_t *quote;
            json::JSON req_json = json::JSON::Load(req.body());
            p_log->info("request body:%s\n", req_json.dump().c_str());
            std::string b64quote = req_json["isvEnclaveQuote"].ToString();
            std::string off_chain_chain_address = req_json["chain_address"].ToString();
            std::string off_chain_chain_account_id = req_json["chain_account_id"].ToString();
            std::string signature_str = req_json["signature"].ToString();
            std::string data_sig_str;
            data_sig_str.append(b64quote)
                .append(off_chain_chain_address)
                .append(off_chain_chain_account_id);
            sgx_ec256_signature_t data_sig;
            memset(&data_sig, 0, sizeof(sgx_ec256_signature_t));
            memcpy(&data_sig, hex_string_to_bytes(signature_str.c_str(), signature_str.size()),
                   sizeof(sgx_ec256_signature_t));

            if (!get_quote_size(&status_ret, &qsz))
            {
                p_log->err("PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
                res.body() = "InternalError";
                res.result(400);
                goto postcleanup;
            }

            if (b64quote.size() == 0)
            {
                res.body() = "InternalError";
                res.result(400);
                goto postcleanup;
            }

            quote = (sgx_quote_t *)malloc(qsz);
            memset(quote, 0, qsz);
            memcpy(quote, base64_decode(b64quote.c_str(), &dqsz), qsz);

            status_ret = ecall_store_quote(global_eid, &crust_status, (const char *)quote, qsz, (const uint8_t *)data_sig_str.c_str(),
                    data_sig_str.size(), &data_sig, (const uint8_t *)off_chain_chain_account_id.c_str(), off_chain_chain_account_id.size());
            if (SGX_SUCCESS != status_ret || CRUST_SUCCESS != crust_status)
            {
                p_log->err("Store and verify offChain node data failed!\n");
                res.body() = "StoreQuoteError";
                res.result(401);
                goto postcleanup;
            }
            p_log->info("Storing quote in enclave successfully!\n");

            // Request IAS verification
            httplib::SSLClient *client = new httplib::SSLClient(p_config->ias_base_url);
            httplib::Headers headers = {
                {"Ocp-Apim-Subscription-Key", p_config->ias_primary_subscription_key}
                //{"Content-Type", "application/json"}
            };
            client->set_timeout_sec(IAS_TIMEOUT);

            std::string body = "{\n\"isvEnclaveQuote\":\"";
            body.append(b64quote);
            body.append("\"\n}");

            std::string resStr;
            json::JSON res_json;
            std::shared_ptr<httplib::Response> ias_res;

            // Send quote to IAS service
            int net_tryout = IAS_TRYOUT;
            while (net_tryout > 0)
            {
                ias_res = client->Post(p_config->ias_base_path.c_str(), headers, body, "application/json");
                if (!(ias_res && ias_res->status == 200))
                {
                    p_log->err("Send to IAS failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
                    sleep(3);
                    net_tryout--;
                    continue;
                }
                break;
            }

            if (!(ias_res && ias_res->status == 200))
            {
                p_log->err("Request IAS failed!\n");
                res.body() = "Request IAS failed!";
                res.result(402);
                delete client;
                goto postcleanup;
            }
            res_json = json::JSON::Load(ias_res->body);
            p_log->info("Sending quote to IAS service successfully!\n");

            httplib::Headers res_headers = ias_res->headers;
            std::vector<const char *> ias_report;
            ias_report.push_back(res_headers.find("X-IASReport-Signing-Certificate")->second.c_str());
            ias_report.push_back(res_headers.find("X-IASReport-Signature")->second.c_str());
            ias_report.push_back(ias_res->body.c_str());

            // Identity info
            ias_report.push_back(off_chain_chain_account_id.c_str()); //[3]
            ias_report.push_back(p_config->chain_account_id.c_str()); //[4]

            p_log->debug("\n\n----------IAS Report - JSON - Required Fields----------\n\n");
            if (version >= 3)
            {
                p_log->debug("version               = %ld\n",
                            res_json["version"].ToInt());
            }
            p_log->debug("id:                   = %s\n",
                        res_json["id"].ToString().c_str());
            p_log->debug("timestamp             = %s\n",
                        res_json["timestamp"].ToString().c_str());
            p_log->debug("isvEnclaveQuoteStatus = %s\n",
                        res_json["isvEnclaveQuoteStatus"].ToString().c_str());
            p_log->debug("isvEnclaveQuoteBody   = %s\n",
                        res_json["isvEnclaveQuoteBody"].ToString().c_str());
            std::string iasQuoteStr = res_json["isvEnclaveQuoteBody"].ToString();
            size_t qs;
            char *ppp = base64_decode(iasQuoteStr.c_str(), &qs);
            sgx_quote_t *ias_quote = (sgx_quote_t *)malloc(qs);
            memset(ias_quote, 0, qs);
            memcpy(ias_quote, ppp, qs);
            p_log->debug("========== ias quote report data:%s\n", hexstring(ias_quote->report_body.report_data.d, sizeof(ias_quote->report_body.report_data.d)));
            p_log->debug("ias quote report version:%d\n", ias_quote->version);
            p_log->debug("ias quote report signtype:%d\n", ias_quote->sign_type);
            p_log->debug("ias quote report basename:%s\n", hexstring(&ias_quote->basename, sizeof(sgx_basename_t)));
            p_log->debug("ias quote report mr_enclave:%s\n", hexstring(&ias_quote->report_body.mr_enclave, sizeof(sgx_measurement_t)));

            p_log->debug("\n\n----------IAS Report - JSON - Optional Fields----------\n\n");

            p_log->debug("platformInfoBlob  = %s\n",
                        res_json["platformInfoBlob"].ToString().c_str());
            p_log->debug("revocationReason  = %s\n",
                        res_json["revocationReason"].ToString().c_str());
            p_log->debug("pseManifestStatus = %s\n",
                        res_json["pseManifestStatus"].ToString().c_str());
            p_log->debug("pseManifestHash   = %s\n",
                        res_json["pseManifestHash"].ToString().c_str());
            p_log->debug("nonce             = %s\n",
                        res_json["nonce"].ToString().c_str());
            p_log->debug("epidPseudonym     = %s\n",
                        res_json["epidPseudonym"].ToString().c_str());

            // Verify IAS report in enclave
            entry_network_signature ensig;
            status_ret = ecall_verify_iasreport(global_eid, &crust_status, const_cast<char**>(ias_report.data()), ias_report.size(), &ensig);
            if (SGX_SUCCESS == status_ret)
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    json::JSON identity_json;
                    identity_json["pub_key"] = hexstring((const char *)&ensig.pub_key, sizeof(ensig.pub_key));
                    identity_json["account_id"] = off_chain_chain_address;
                    identity_json["validator_pub_key"] = hexstring((const char *)&ensig.validator_pub_key, sizeof(ensig.validator_pub_key));
                    identity_json["validator_account_id"] = p_config->chain_address;
                    identity_json["sig"] = hexstring((const char *)&ensig.signature, sizeof(ensig.signature));
                    std::string jsonstr = identity_json.dump();
                    // Delete space
                    jsonstr.erase(std::remove(jsonstr.begin(), jsonstr.end(), ' '), jsonstr.end());
                    // Delete line break
                    jsonstr.erase(std::remove(jsonstr.begin(), jsonstr.end(), '\n'), jsonstr.end());

                    p_log->info("Verify IAS report in enclave successfully!\n");
                    res.body() = jsonstr.c_str();
                }
                else
                {
                    switch (crust_status)
                    {
                    case CRUST_IAS_BADREQUEST:
                        p_log->err("Verify IAS report failed! Bad request!!\n");
                        break;
                    case CRUST_IAS_UNAUTHORIZED:
                        p_log->err("Verify IAS report failed! Unauthorized!!\n");
                        break;
                    case CRUST_IAS_NOT_FOUND:
                        p_log->err("Verify IAS report failed! Not found!!\n");
                        break;
                    case CRUST_IAS_SERVER_ERR:
                        p_log->err("Verify IAS report failed! Server error!!\n");
                        break;
                    case CRUST_IAS_UNAVAILABLE:
                        p_log->err("Verify IAS report failed! Unavailable!!\n");
                        break;
                    case CRUST_IAS_INTERNAL_ERROR:
                        p_log->err("Verify IAS report failed! Internal error!!\n");
                        break;
                    case CRUST_IAS_BAD_CERTIFICATE:
                        p_log->err("Verify IAS report failed! Bad certificate!!\n");
                        break;
                    case CRUST_IAS_BAD_SIGNATURE:
                        p_log->err("Verify IAS report failed! Bad signature!!\n");
                        break;
                    case CRUST_IAS_REPORTDATA_NE:
                        p_log->err("Verify IAS report failed! Report data not equal!!\n");
                        break;
                    case CRUST_IAS_GET_REPORT_FAILED:
                        p_log->err("Verify IAS report failed! Get report in current enclave failed!!\n");
                        break;
                    case CRUST_IAS_BADMEASUREMENT:
                        p_log->err("Verify IAS report failed! Bad enclave code measurement!!\n");
                        break;
                    case CRUST_IAS_UNEXPECTED_ERROR:
                        p_log->err("Verify IAS report failed! unexpected error!!\n");
                        break;
                    case CRUST_IAS_GETPUBKEY_FAILED:
                        p_log->err("Verify IAS report failed! Get public key from certificate failed!!\n");
                        break;
                    case CRUST_SIGN_PUBKEY_FAILED:
                        p_log->err("Sign public key failed!!\n");
                        break;
                    default:
                        p_log->err("Unknown return status!\n");
                    }
                    res.body() = "Verify IAS report failed!";
                    res.result(403);
                }
            }
            else
            {
                p_log->err("Invoke SGX api failed!\n");
                res.body() = "Invoke SGX api failed!";
                res.result(404);
            }
            delete client;
            goto postcleanup;
        }


        // Inner APIs
        cur_path = urlendpoint->base + "/change/empty";
        if (path.compare(cur_path) == 0)
        {
            if (!is_ssl)
            {
                res.body() = "Insecure http request!Please use https request!";
                res.result(300);
                goto postcleanup;
            }
            res.result(200);
            std::string error_info;
            // Get backup info
            if (req.find("backup") == req.end())
            {
                error_info = "Validate MerkleTree failed!Error: Empty backup!";
                res.result(400);
            }
            else if (p_config->chain_backup.compare(std::string(req.at("backup"))) != 0)
            {
                error_info = "Validate MerkleTree failed!Error: Invalid backup!";
                res.result(401);
            }
            if (int(res.result()) != 200)
            {
                p_log->err("%s\n", error_info.c_str());
                res.body() = error_info;
                goto postcleanup;
            }
            // Guaranteed that only one service is running
            change_empty_mutex.lock();
            if (in_changing_empty)
            {
                p_log->info("Change empty service busy\n");
                res.body() = "Change empty service busy";
                res.result(500);
                change_empty_mutex.unlock();
                goto postcleanup;
            }
            in_changing_empty = true;
            change_empty_mutex.unlock();

            // Check input parameters
            json::JSON req_json = json::JSON::Load(req.body());
            change_empty_num = req_json["change"].ToInt();

            if (change_empty_num == 0)
            {
                p_log->info("Invalid change\n");
                res.body() = "Invalid change";
                res.result(402);
                goto end_change_empty;
            }
            else
            {
                // Check TEE has already launched
                validation_status_t validation_status = VALIDATE_STOP;

                if (ecall_return_validation_status(global_eid, &validation_status) != SGX_SUCCESS)
                {
                    p_log->info("Get validation status failed.\n");
                    res.body() = "Get validation status failed";
                    res.result(500);
                    goto end_change_empty;
                }
                else if (validation_status == VALIDATE_STOP)
                {
                    p_log->info("TEE has not been fully launched.\n");
                    res.body() = "TEE has not been fully launched";
                    res.result(500);
                    goto end_change_empty;
                }

                // Start changing empty
                pthread_t wthread;
                if (pthread_create(&wthread, NULL, ApiHandler::change_empty, NULL) != 0)
                {
                    p_log->err("Create change empty thread error.\n");
                    res.body() = "Create change empty thread error";
                    res.result(500);
                    goto end_change_empty;
                }
                else
                {
                    res.body() = "Change empty file success, the empty workload will change in next validation loop";
                    goto postcleanup;
                }
            }
        end_change_empty:
            change_empty_mutex.lock();
            in_changing_empty = false;
            change_empty_mutex.unlock();
            goto postcleanup;
        }

    postcleanup:
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.content_length(res.body().size());
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }
}
*/
