#ifndef _CRUST_API_HANDLER_H_
#define _CRUST_API_HANDLER_H_

#include <stdio.h>
#include <algorithm>
#include <mutex>
#include <exception>
#include <sgx_report.h>
#include <sgx_key_exchange.h>
#include <sgx_error.h>
#include "Enclave_u.h"
#include "sgx_eid.h"
#include "Common.h"
#include "Config.h"
#include "FormatUtils.h"
#include "IASReport.h"
#include "SgxSupport.h"
#include "Resource.h"
#include "HttpClient.h"
#include "FileUtils.h"
#include "Log.h"
#include "Json.hpp"
#include "sgx_tseal.h"
#include "Config.h"
#include "Common.h"

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#define WS_SEPARATOR "$crust_ws_separator$"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>

class WebServer;

class ApiHandler
{
public:
    std::string websocket_handler(std::string &path, std::string &data, bool &close_connection);
    template<class Body, class Allocator, class Send>
    void http_handler(beast::string_view doc_root,
        http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, bool is_ssl);
    //void ApiHandler::http_handler(beast::string_view doc_root,
    //    http::request<http::basic_fields<http::string_body>>&& req, Queue&& send, bool is_ssl)

private:
    static void *change_empty(void *);
    std::shared_ptr<WebServer> server = NULL;
    std::vector<uint8_t> root_hash_v;
    long block_left_num;
    long block_num;
    bool seal_check_validate = false;
    bool unseal_check_backup = false;
    MerkleTree *tree_root = NULL;
};

std::string path_cat(beast::string_view base, beast::string_view path);
std::map<std::string, std::string> get_params(std::string &url);

extern sgx_enclave_id_t global_eid;
extern std::map<std::string, std::string> sealed_tree_map;
// Used to show validation status
const char *validation_status_strings[] = {"validate_stop", "validate_waiting", "validate_meaningful", "validate_empty"};
bool in_changing_empty = false;
std::mutex change_empty_mutex;
int change_empty_num = 0;

// TODO: Should limit thread number in enclave
/**
 * @desination: Start rest service
 * @return: Start status
 * */
template<class Body, class Allocator, class Send>
void ApiHandler::http_handler(beast::string_view /*doc_root*/,
    http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, bool is_ssl)
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
        //res.keep_alive(req.keep_alive());
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
        //res.keep_alive(req.keep_alive());
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

            char *report = (char*)malloc(report_len);
            memset(report, 0, report_len);
            if (ecall_get_work_report(global_eid, &crust_status, report, report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
            {
                p_log->err("Get validation report failed.\n");
                res.body() = "InternalError";
                free(report);
                goto getcleanup;
            }

            if (report == NULL)
            {
                res.body() = "InternalError";
                free(report);
                goto getcleanup;
            }

            res.body() = std::string(report, report_len);
            free(report);
            goto getcleanup;
        }


    getcleanup:

        res.content_length(res.body().size());
        //res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }


    // Respond to POST request
    if(req.method() == http::verb::post)
    {
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("crust return"),
            std::make_tuple(http::status::ok, req.version())};
        res.result(400);
        res.body() = "Unknown request!";
        json::JSON res_json;

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

            // ----- Request IAS verification ----- //
            HttpClient *client = new HttpClient();
            ApiHeaders headers = {
                {"Ocp-Apim-Subscription-Key", p_config->ias_primary_subscription_key}
                //{"Content-Type", "application/json"}
            };
            std::string body = "{\n\"isvEnclaveQuote\":\"";
            body.append(b64quote);
            body.append("\"\n}");
            std::string resStr;
            http::response<http::string_body> ias_res;
            // Send quote to IAS service
            int net_tryout = IAS_TRYOUT;
            while (net_tryout > 0)
            {
                ias_res = client->SSLPost(p_config->ias_base_url+p_config->ias_base_path, body, "application/json", headers);
                if ((int)ias_res.result() != 200)
                {
                    p_log->err("Send to IAS failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
                    sleep(3);
                    net_tryout--;
                    continue;
                }
                break;
            }

            if ((int)ias_res.result() != 200)
            {
                p_log->err("Request IAS failed!\n");
                res.body() = "Request IAS failed!";
                res.result(402);
                delete client;
                goto postcleanup;
            }
            p_log->info("Sending quote to IAS service successfully!\n");

            std::vector<const char *> ias_report;
            std::string ias_cer(ias_res["X-IASReport-Signing-Certificate"]);
            std::string ias_sig(ias_res["X-IASReport-Signature"]);
            ias_report.push_back(ias_cer.c_str());
            ias_report.push_back(ias_sig.c_str());
            ias_report.push_back(ias_res.body().c_str());

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

        // Storage seal file block
        cur_path = urlendpoint->base + "/storage/seal";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            res.result(200);
            std::string error_info;
            crust_status_t crust_status = CRUST_SUCCESS;
            sgx_status_t sgx_status = SGX_SUCCESS;

            p_log->info("Dealing with seal request...\n");

            // ----- Validate MerkleTree ----- //
            json::JSON req_json;
            try
            {
                req_json = json::JSON::Load(req.body());
            }
            catch (std::exception e)
            {
                error_info.append("Validate MerkleTree failed! Parse json failed! Error: ").append(e.what());
                p_log->err("%s\n", error_info.c_str());
                res_json["body"] = error_info;
                res.result(400);
                res.body() = res_json.dump();
                goto postcleanup;
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
                res.result(401);
                p_log->err("%s\n", error_info.c_str());
                res_json["body"] = error_info;
                res.body() = res_json.dump();
                goto postcleanup;
            }
            // Check if body is validated
            if (body_json.size() == 0)
            {
                error_info = "Validate MerkleTree failed!Error: Empty body!";
                p_log->err("%s\n", error_info.c_str());
                res_json["body"] = error_info;
                res.result(402);
                res.body() = res_json.dump();
                goto postcleanup;
            }

            // Get MerkleTree
            MerkleTree *root = deserialize_merkle_tree_from_json(body_json);
            if (root == NULL)
            {
                p_log->err("Deserialize MerkleTree failed!\n");
                res_json["body"] = "Deserialize MerkleTree failed!";
                res.result(403);
                res.body() = res_json.dump();
                goto postcleanup;
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
                res_json["body"] = error_info;
                res.result(404);
                res.body() = res_json.dump();
                goto postcleanup;
            }
            else
            {
                if (CRUST_MERKLETREE_DUPLICATED == crust_status)
                {
                    res.result(201);
                    res_json["body"] = "MerkleTree has been validated!";
                }
                else
                {
                    p_log->info("Validate merkle tree successfully!\n");
                }
                seal_check_validate = true;
            }


            // ----- Seal file ----- //
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
                p_log->err("Seal data failed!Error code:%lx(%s)\n", crust_status, error_info.c_str());
                res_json["body"] = error_info;
                res.result(405);
            }
            else
            {
                p_log->info("Seal file successfully!\n");
                std::string tree_str = sealed_tree_map[org_root_hash_str];
                remove_char(tree_str, ' ');
                remove_char(tree_str, '\n');
                remove_char(tree_str, '\\');
                res_json["body"] = tree_str;
                res_json["path"] = std::string(p_new_path, dir_path.size());
                sealed_tree_map.erase(org_root_hash_str);
            }

            std::string res_str = res_json.dump();
            remove_char(res_str, '\\');
            res.body() = res_str;

            free(p_new_path);

            goto postcleanup;
        }


        // Storage unseal file block
        cur_path = urlendpoint->base + "/storage/unseal";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            res.result(200);
            std::string error_info;

            p_log->info("Dealing with unseal request...\n");

            // Parse parameters
            json::JSON req_json;
            try
            {
                req_json = json::JSON::Load(req.body());
            }
            catch (std::exception e)
            {
                error_info.append("Unseal file failed! Parse json failed! Error: ").append(e.what());
                p_log->err("%s\n", error_info.c_str());
                res_json["body"] = error_info;
                res.result(400);
                res.body() = res_json.dump();
                goto postcleanup;
            }

            std::string dir_path = req_json["path"].ToString();
            std::string backup = req_json["backup"].ToString();

            // Check backup
            remove_char(backup, '\\');
            if (p_config->chain_backup.compare(backup) != 0)
            {
                error_info = "Unseal data failed!Invalid backup!";
                p_log->err("%s\n", error_info.c_str());
                res_json["body"] = error_info;
                res.result(401);
                res.body() = res_json.dump();
                goto postcleanup;
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
                res.result(402);
                res_json["body"] = error_info;
                res.body() = res_json.dump();
                goto postcleanup;
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
                res_json["body"] = error_info;
                res.result(403);
            }
            else
            {
                p_log->info("Unseal data successfully!\n");
                res_json["body"] = "Unseal data successfully!";
                res_json["path"] = std::string(p_new_path, dir_path.size());
            }

            std::string res_str = res_json.dump();
            remove_char(res_str, '\\');
            res.body() = res_str;

            free(p_new_path);

            goto postcleanup;
        }

    postcleanup:
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.content_length(res.body().size());
        //res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }
}

#endif /* !_CRUST_API_HANDLER_H_ */
