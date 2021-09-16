#ifndef _CRUST_API_HANDLER_H_
#define _CRUST_API_HANDLER_H_

#include <stdio.h>
#include <mutex>
#include <set>
#include <vector>
#include <exception>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/strand.hpp>

#include <sgx_report.h>
#include <sgx_key_exchange.h>
#include <sgx_error.h>
#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "ECalls.h"
#include "FormatUtils.h"
#include "IASReport.h"
#include "SgxSupport.h"
#include "Resource.h"
#include "HttpClient.h"
#include "FileUtils.h"
#include "Log.h"
#include "Config.h"
#include "Common.h"
#include "DataBase.h"
#include "Srd.h"
#include "EnclaveData.h"
#include "Chain.h"
#include "../../enclave/utils/Defer.h"

#ifdef _CRUST_TEST_FLAG_
#include "ApiHandlerTest.h"
extern size_t g_block_height;
#endif

#define WS_SEPARATOR "$crust_ws_separator$"
#define IPFS_INDEX_LENGTH 512

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
    std::shared_ptr<WebServer> server = NULL;
    std::vector<uint8_t> root_hash_v;
    bool unseal_check_backup = false;
    MerkleTree *tree_root = NULL;

    // Upgrade block service set
    const std::set<std::string> upgrade_block_s = {
        "/srd/change",
        "/storage/delete",
        "/storage/seal_start",
    };
    const std::set<std::string> http_mute_req_s = {
        "/workload",
        "/enclave/id_info",
        "/storage/seal",
        "/storage/unseal",
        "/file/info",
        "/file/info_by_type",
    };
    const std::set<std::string> sealed_file_types = {
        "all",
        FILE_TYPE_PENDING,
        FILE_TYPE_VALID,
        FILE_TYPE_LOST,
    };
};

std::string path_cat(beast::string_view base, beast::string_view path);
std::map<std::string, std::string> get_params(std::string &url);

extern sgx_enclave_id_t global_eid;
// Used to show validation status
long change_srd_num = 0;

/**
 * @description: Start rest service
 * @return: Start status
 */
template<class Body, class Allocator, class Send>
void ApiHandler::http_handler(beast::string_view /*doc_root*/,
    http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, bool /*is_ssl*/)
{
    Config *p_config = Config::get_instance();
    crust::Log *p_log = crust::Log::get_instance();
    UrlEndPoint urlendpoint = get_url_end_point(p_config->base_url);
    EnclaveData *ed = EnclaveData::get_instance();
    EnclaveQueue *eq = EnclaveQueue::get_instance();
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
    std::string req_route = std::string(req.target().data(), req.target().size());
    if (memcmp(req_route.c_str(), urlendpoint.base.c_str(), urlendpoint.base.size()) != 0)
    {
        return send(bad_request("Illegal request-target"));
    }

    // Get request real route
    std::map<std::string, std::string> params_m = get_params(req_route);
    req_route = params_m["req_route"];
    std::string route_tag = req_route.substr(req_route.find(urlendpoint.base) + urlendpoint.base.size(), req_route.size());
    if (http_mute_req_s.find(route_tag) == http_mute_req_s.end())
    {
        p_log->info("Http request:%s\n", req_route.c_str());
    }

    // Choose service according to upgrade status
    if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status())
    {
        p_log->warn("This process will exit!\n");
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("Stop service!"),
            std::make_tuple(http::status::forbidden, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        json::JSON ret_body;
        ret_body[HTTP_STATUS_CODE] = 501;
        ret_body[HTTP_MESSAGE] = "No service will be provided because of upgrade!";
        res.result(ret_body[HTTP_STATUS_CODE].ToInt());
        res.body() = ret_body.dump();
        return send(std::move(res));
    }
    if (UPGRADE_STATUS_NONE != ed->get_upgrade_status() 
            && UPGRADE_STATUS_STOP_WORKREPORT != ed->get_upgrade_status()
            && upgrade_block_s.find(route_tag) != upgrade_block_s.end())
    {
        p_log->warn("Upgrade is doing, %s request cannot be applied!\n", route_tag.c_str());
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("Current service is closed due to upgrade!"),
            std::make_tuple(http::status::forbidden, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        json::JSON ret_body;
        ret_body[HTTP_STATUS_CODE] = 501;
        ret_body[HTTP_MESSAGE] = "Current service is closed due to upgrade!";
        res.result(ret_body[HTTP_STATUS_CODE].ToInt());
        res.body() = ret_body.dump();
        return send(std::move(res));
    }

    // ----- Respond to HEAD request ----- //
    if(req.method() == http::verb::head)
    {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }

    http::response<http::string_body> res{
        std::piecewise_construct,
        std::make_tuple("Unknown request target"),
        std::make_tuple(http::status::bad_request, req.version())};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "application/text");

#ifdef _CRUST_TEST_FLAG_
    json::JSON req_json;
    req_json["target"] = req_route;
    req_json["method"] = req.method() == http::verb::get ? "GET" : "POST";
    req_json["body"] = std::string(reinterpret_cast<const char *>(req.body().data()), req.body().size());
    json::JSON test_res = http_handler_test(urlendpoint, req_json);
    if (test_res.size() > 0)
    {
        res.result(test_res[HTTP_STATUS_CODE].ToInt());
        std::string res_body = test_res[HTTP_MESSAGE].ToString();
        remove_char(res_body, '\\');
        res.body() = res_body;
        res.content_length(res.body().size());
        return send(std::move(res));
    }
#endif

    // ----- Respond to GET request ----- //
    if(req.method() == http::verb::get)
    {
        // ----- Get workload ----- //
        cur_path = urlendpoint.base + "/workload";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            res.body() = EnclaveData::get_instance()->gen_workload_str();
            goto getcleanup;
        }

        // ----- Stop sworker ----- //
        cur_path = urlendpoint.base + "/stop";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            std::string ret_info;
            int ret_code = 400;
            if (SGX_SUCCESS != Ecall_stop_all(global_eid))
            {
                ret_info = "Stop enclave failed! Invoke SGX API failed!";
                ret_code = 500;
                p_log->err("%s\n", ret_info.c_str());
            }
            else
            {
                ret_info = "Stop sworker successfully.";
                ret_code = 200;
                // We just need to wait workreport and storing metadata, and then can stop
                while (eq->has_stopping_block_task())
                {
                    sleep(1);
                }
                ed->set_upgrade_status(UPGRADE_STATUS_EXIT);
                p_log->info("%s\n", ret_info.c_str());
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.body() = ret_body.dump();

            goto getcleanup;
        }

        // ----- Get enclave thread information ----- //
        cur_path = urlendpoint.base + "/enclave/thread_info";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            res.body() = eq->get_running_ecalls_info();
            goto getcleanup;
        }

        // ----- Get enclave id information ----- //
        cur_path = urlendpoint.base + "/enclave/id_info";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            std::string id_info_str = ed->get_enclave_id_info();
            if (id_info_str.compare("") == 0)
            {
                json::JSON ret_body;
                ret_body[HTTP_STATUS_CODE] = 400;
                ret_body[HTTP_MESSAGE] = "Get id info failed!Invoke SGX API failed!";
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
            }
            else
            {
                json::JSON id_json = json::JSON::Load_unsafe(id_info_str);
                id_json["account"] = p_config->chain_address;
                id_json["version"] = VERSION;
                id_json["sworker_version"] = SWORKER_VERSION;
                res.body() = id_json.dump();
                res.result(200);
            }
            goto getcleanup;
        }

        // ----- Get sealed file information by cid ----- //
        cur_path = urlendpoint.base + "/file/info";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            int ret_code = 400;
            std::string ret_info;
            json::JSON ret_body;
            std::string param_name = "cid";
            if (params_m.find(param_name) == params_m.end())
            {
                ret_info = "Bad parameter! Need a string type parameter:'" + param_name + "'";
                ret_code = 400;
            }
            else
            {
                std::string cid = params_m[param_name];
                json::JSON ret_body;
                std::string file_info = EnclaveData::get_instance()->get_file_info(cid);
                if (file_info.compare("") == 0)
                {
                    ret_info = "File not found.";
                    ret_code = 404;
                }
                else
                {
                    res.result(200);
                    res.body() = file_info;
                    goto getcleanup;
                }
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();
            goto getcleanup;
        }

        // ----- Get sealed file information by type ----- //
        cur_path = urlendpoint.base + "/file/info_by_type";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            std::string param_name = "type";
            bool bad_req = false;
            if (params_m.find(param_name) == params_m.end())
            {
                bad_req = true;
            }
            else
            {
                std::string type = params_m[param_name];
                if (sealed_file_types.find(type) == sealed_file_types.end())
                {
                    bad_req = true;
                }
                else
                {
                    if (type.compare("all") == 0)
                    {
                        res.body() = EnclaveData::get_instance()->get_file_info_all();
                    }
                    else
                    {
                        res.body() = EnclaveData::get_instance()->get_file_info_by_type(type);
                    }
                }
            }
            if (bad_req)
            {
                json::JSON ret_body;
                ret_body[HTTP_STATUS_CODE] = 400;
                ret_body[HTTP_MESSAGE] = "Bad parameter! Need a string type parameter:'" + param_name + "' which should be 'all', 'pending', 'valid', 'lost'";
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
            }
            goto getcleanup;
        }

        // ----- Inform upgrade ----- //
        cur_path = urlendpoint.base + "/upgrade/start";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            int ret_code = 400;
            json::JSON ret_body;
            std::string ret_info;
            if (UPGRADE_STATUS_NONE != ed->get_upgrade_status()
                    && UPGRADE_STATUS_STOP_WORKREPORT != ed->get_upgrade_status())
            {
                ret_body[HTTP_STATUS_CODE] = 502;
                ret_body[HTTP_MESSAGE] = "Another upgrading is still running!";
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
                goto getcleanup;
            }

            // Block current work-report for a while
            ed->set_upgrade_status(UPGRADE_STATUS_STOP_WORKREPORT);

            sgx_status_t sgx_status = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            crust::BlockHeader block_header;
            if (!crust::Chain::get_instance()->get_block_header(block_header))
            {
                ret_info = "Chain is not running!Get block header failed!";
                ret_code = 400;
                p_log->err("%s\n", ret_info.c_str());
            }
            else if (SGX_SUCCESS != (sgx_status = Ecall_enable_upgrade(global_eid, &crust_status, block_header.number)))
            {
                ret_info = "Invoke SGX API failed!";
                ret_code = 500;
                p_log->err("%sError code:%lx\n", ret_info.c_str(), sgx_status);
            }
            else
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    ret_info = "Receive upgrade inform successfully!";
                    ret_code = 200;
                    // Set upgrade status
                    ed->set_upgrade_status(UPGRADE_STATUS_PROCESS);
                    // Give current tasks some time to go into enclave queue.
                    sleep(10);
                    p_log->info("%s\n", ret_info.c_str());
                }
                else
                {
                    switch (crust_status)
                    {
                        case CRUST_UPGRADE_BLOCK_EXPIRE:
                            ret_info = "Block expired!Wait for next report slot(" + std::to_string(REPORT_SLOT) + " blocks).";
                            ret_code = 400;
                            break;
                        case CRUST_UPGRADE_NO_VALIDATE:
                            ret_info = "Necessary validation not completed!";
                            ret_code = 400;
                            break;
                        case CRUST_UPGRADE_RESTART:
                            ret_info = "Cannot report due to restart!Wait for report slot(" + std::to_string(REPORT_SLOT) + " blocks).";
                            ret_code = 400;
                            break;
                        case CRUST_UPGRADE_NO_FILE:
                            ret_info = "Cannot get files for check!Please check ipfs!";
                            ret_code = 400;
                            break;
                        default:
                            ret_info = "Unknown error.";
                            ret_code = 400;
                    }
                }
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();

            goto getcleanup;
        }

        // ----- Get upgrade metadata ----- //
        cur_path = urlendpoint.base + "/upgrade/metadata";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            if (UPGRADE_STATUS_COMPLETE != ed->get_upgrade_status())
            {
                json::JSON ret_body;
                ret_body[HTTP_STATUS_CODE] = 502;
                ret_body[HTTP_MESSAGE] = "Metadata is still collecting!";
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
            }
            else
            {
                std::string upgrade_data = ed->get_upgrade_data();
                p_log->info("Generate upgrade data successfully!Data size:%ld.\n", upgrade_data.size());
                res.result(200);
                res.body() = upgrade_data;
            }

            goto getcleanup;
        }

        // ----- Inform current sworker upgrade result ----- //
        cur_path = urlendpoint.base + "/upgrade/complete";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            int ret_code = 200;
            std::string ret_info;
            json::JSON ret_body;
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_name = "success";
            if (!req_json.hasKey(param_name) || req_json[param_name].JSONType() != json::JSON::Class::Boolean)
            {
                ret_info = "Bad parameter! Need a boolean type parameter:'" + param_name + "'";
                ret_code = 400;
                ret_body[HTTP_STATUS_CODE] = ret_code;
                ret_body[HTTP_MESSAGE] = ret_info;
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
            }
            else
            {
                bool upgrade_ret = req_json[param_name].ToBool();
                crust_status_t crust_status = CRUST_SUCCESS;
                if (!upgrade_ret)
                {
                    ret_info = "Upgrade failed! Current version will restore work.";
                    p_log->err("%s\n", ret_info.c_str());
                    ed->set_upgrade_status(UPGRADE_STATUS_NONE);
                }
                else
                {
                    if (UPGRADE_STATUS_COMPLETE == ed->get_upgrade_status())
                    {
                        // Store old metadata to ID_METADATA_OLD
                        crust::DataBase *db = crust::DataBase::get_instance();
                        std::string metadata_old;
                        if (CRUST_SUCCESS != (crust_status = db->get(ID_METADATA, metadata_old)))
                        {
                            ret_info = "Upgrade: get old metadata failed!Status code:" + num_to_hexstring(crust_status);
                            p_log->warn("%s\n", ret_info.c_str());
                        }
                        else
                        {
                            if (CRUST_SUCCESS != (crust_status = db->set(ID_METADATA_OLD, metadata_old)))
                            {
                                ret_info = "Upgrade: store old metadata failed!Status code:" + num_to_hexstring(crust_status);
                                p_log->warn("%s\n", ret_info.c_str());
                            }
                        }
                        if (CRUST_SUCCESS != (crust_status = db->del(ID_METADATA)))
                        {
                            ret_info = "Upgrade: delete old metadata failed!Status code:" + num_to_hexstring(crust_status);
                            p_log->warn("%s\n", ret_info.c_str());
                        }
                        else
                        {
                            ret_info = "Upgrade: clean old version's data successfully!";
                            p_log->info("%s\n", ret_info.c_str());
                        }
                        // Set upgrade exit flag
                        ed->set_upgrade_status(UPGRADE_STATUS_EXIT);
                    }
                    else
                    {
                        ret_info = "Cannot exit upgrade because of unexpected upgrade status!";
                        p_log->err("%s\n", ret_info.c_str());
                    }
                }
                ret_body[HTTP_STATUS_CODE] = std::stoi(num_to_hexstring(crust_status), NULL, 10);
                ret_body[HTTP_MESSAGE] = ret_info;
                res.body() = ret_body.dump();
            }

            goto getcleanup;
        }


    getcleanup:

        res.content_length(res.body().size());
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }


    // ----- Respond to POST request ----- //
    if(req.method() == http::verb::post)
    {
        res.result(400);
        res.body() = "Unknown request!";
        json::JSON res_json;


        // ----- Set debug flag ----- //
        cur_path = urlendpoint.base + "/debug";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            // Check input parameters
            std::string ret_info;
            int ret_code = 400;
            json::JSON ret_body;
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_name = "debug";
            if (!req_json.hasKey(param_name) || req_json[param_name].JSONType() != json::JSON::Class::Boolean)
            {
                ret_info = "Bad parameter! Need a boolean type parameter:'" + param_name + "'";
                ret_code = 400;
            }
            else
            {
                bool debug_flag = req_json[param_name].ToBool();
                p_log->set_debug(debug_flag);
                ret_info = "Set debug flag successfully!";
                p_log->info("%s %s debug.\n", ret_info.c_str(), debug_flag ? "Open" : "Close");
                ret_code = 200;
                // Store debug flag
                crust_status_t ret = crust::DataBase::get_instance()->set(DB_DEBUG, std::to_string(debug_flag));
                if (CRUST_SUCCESS != ret)
                {
                    p_log->debug("Cannot store debug flag in db, code:%lx\n", ret);
                }
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();
            goto postcleanup;
        }

        // ----- Set config path ----- //
        cur_path = urlendpoint.base + "/config/add_path";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            int ret_code = 400;
            std::string ret_info;
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            json::JSON ret_body;

            if (!p_config->config_file_add_data_paths(req_json))
            {
                ret_info = "Add data paths to config failed!";
                p_log->err("%s\n", ret_info.c_str());
                ret_code = 400;
            }
            else
            {
                ret_info = "Change config data path successfully!";
                p_log->err("%s\n", ret_info.c_str());
                ret_code = 200;
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();
            goto postcleanup;
        }

        // --- Change srd --- //
        cur_path = urlendpoint.base + "/srd/change";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            // Check input parameters
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_name = "change";
            if (!req_json.hasKey(param_name) || req_json[param_name].JSONType() != json::JSON::Class::Integral)
            {
                ret_info = "Bad parameter! Need a integral type parameter:'" + param_name + "'";
                ret_code = 400;
            }
            else
            {
                change_srd_num = req_json[param_name].ToInt();
                if (change_srd_num == 0)
                {
                    ret_info = "Invalid change";
                    p_log->info("%s\n", ret_info.c_str());
                    ret_code = 400;
                }
                else
                {
                    crust_status_t crust_status = CRUST_SUCCESS;
                    json::JSON wl_info = EnclaveData::get_instance()->gen_workload();
                    long srd_complete = wl_info[WL_SRD][WL_SRD_COMPLETE].ToInt();
                    long srd_remaining_task = wl_info[WL_SRD][WL_SRD_REMAINING_TASK].ToInt();
                    long disk_avail_for_srd = wl_info[WL_SRD][WL_DISK_AVAILABLE_FOR_SRD].ToInt();
                    long running_srd_task = get_running_srd_task();
                    if (change_srd_num > 0)
                    {
                        long avail_space = std::max(disk_avail_for_srd - running_srd_task, (long)0) - srd_remaining_task;
                        long true_increase = std::min(change_srd_num, avail_space);
                        if (true_increase <= 0)
                        {
                            ret_info = "No more srd can be added. Use 'sudo crust tools workload' to check.";
                            ret_code = 400;
                            goto change_end;
                        }
                        change_srd_num = true_increase;
                    }
                    else
                    {
                        long abs_change_srd_num = std::abs(change_srd_num);
                        long avail_space = srd_complete + srd_remaining_task + running_srd_task;
                        long true_decrease = std::min(abs_change_srd_num, avail_space);
                        if (true_decrease <= 0)
                        {
                            ret_info = "No srd space to be deleted. Use 'sudo crust tools workload' to check.";
                            ret_code = 400;
                            goto change_end;
                        }
                        change_srd_num = -true_decrease;
                    }
                    // Start changing srd
                    long real_change = 0;
                    if (SGX_SUCCESS != Ecall_change_srd_task(global_eid, &crust_status, change_srd_num, &real_change))
                    {
                        ret_info = "Change srd failed! Invoke SGX api failed!";
                        ret_code = 500;
                    }
                    else
                    {
                        switch (crust_status)
                        {
                        case CRUST_SUCCESS:
                            ret_info = "Change task:" + std::to_string(real_change) + "G has been added, will be executed later.";
                            ret_code = 200;
                            break;
                        case CRUST_SRD_NUMBER_EXCEED:
                            ret_info = "Only " + std::to_string(real_change) + "G srd will be added. Rest srd task exceeds upper limit.";
                            ret_code = 200;
                            break;
                        case CRUST_UPGRADE_IS_UPGRADING:
                            ret_info = "Change srd interface is stopped due to upgrading or exiting";
                            ret_code = 503;
                            break;
                        default:
                            ret_info = "Unexpected error has occurred!";
                            ret_code = 500;
                        }
                    }
                    p_log->info("%s\n", ret_info.c_str());
                }
            }

        change_end:
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_code);
            res.body() = ret_body.dump();
            goto postcleanup;
        }

        // --- Delete meaningful file --- //
        cur_path = urlendpoint.base + "/storage/delete";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            // Delete file
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_name = "cid";
            if (!req_json.hasKey(param_name) || req_json[param_name].JSONType() != json::JSON::Class::String)
            {
                ret_info = "Bad parameter! Need a string type parameter:'" + param_name + "'";
                ret_code = 400;
            }
            else
            {
                std::string cid = req_json[param_name].ToString();
                sgx_status_t sgx_status = SGX_SUCCESS;
                crust_status_t crust_status = CRUST_SUCCESS;
                if (SGX_SUCCESS != (sgx_status = Ecall_delete_file(global_eid, &crust_status, cid.c_str())))
                {
                    ret_info = "Delete file '" + cid + "' failed! Invoke SGX API failed! Error code:" + num_to_hexstring(sgx_status);
                    p_log->err("%s\n", ret_info.c_str());
                    ret_code = 500;
                }
                else if (CRUST_SUCCESS == crust_status)
                {
                    EnclaveData::get_instance()->del_file_info(cid);
                    ret_info = "Deleting file '" + cid + "' successfully";
                    ret_code = 200;
                }
                else if (CRUST_STORAGE_NEW_FILE_NOTFOUND == crust_status)
                {
                    ret_info = "File '" + cid + "' is not existed in sworker";
                    ret_code = 404;
                }
                else if (CRUST_UPGRADE_IS_UPGRADING == crust_status)
                {
                    ret_info = "Deleting file '" + cid + "' stoped due to upgrading or exiting";
                    ret_code = 503;
                }
                else
                {
                    ret_info = "Unexpected error: " + num_to_hexstring(crust_status);
                    ret_code = 500;
                }  
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();

            goto postcleanup;
        }

        // ----- Seal file start ----- //
        cur_path = urlendpoint.base + "/storage/seal_start";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            crust_status_t crust_status = CRUST_SUCCESS;
            sgx_status_t sgx_status = SGX_SUCCESS;
            // Delete file
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_cid_name = "cid";
            std::string param_cid_b58_name = "cid_b58";
            if (!req_json.hasKey(param_cid_name) 
                || req_json[param_cid_name].JSONType() != json::JSON::Class::String 
                || !req_json.hasKey(param_cid_b58_name) 
                || req_json[param_cid_b58_name].JSONType() != json::JSON::Class::String)
            {
                ret_info = "Bad parameter! Need a string type parameter:'" + param_cid_name + "' or '" + param_cid_b58_name + "'";
                ret_code = 400;
            }
            else
            {
                std::string cid = req_json[param_cid_name].ToString();
                std::string cid_b58 = req_json[param_cid_b58_name].ToString();
                // Do start seal
                if (SGX_SUCCESS != (sgx_status = Ecall_seal_file_start(global_eid, &crust_status, cid.c_str(), cid_b58.c_str())))
                {
                    ret_info = "Start seal file '%s' failed! Invoke SGX API failed! Error code:" + num_to_hexstring(sgx_status);
                    p_log->err("%s\n", ret_info.c_str());
                    ret_code = 500;
                }
                else if (CRUST_SUCCESS != crust_status)
                {
                    switch (crust_status)
                    {
                        case CRUST_FILE_NUMBER_EXCEED:
                            ret_info = "Seal file '" + cid + "' failed! No more file can be sealed! File number reachs the upper limit";
                            p_log->err("%s\n", ret_info.c_str());
                            ret_code = 500;
                            break;
                        case CRUST_UPGRADE_IS_UPGRADING:
                            ret_info = "Seal file '" + cid + "' stopped due to upgrading or exiting";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 503;
                            break;
                        case CRUST_STORAGE_FILE_DUP:
                            ret_info = "This file '" + cid + "' has been sealed";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 200;
                            break;
                        case CRUST_STORAGE_FILE_SEALING:
                            ret_info = "Same file '" + cid + "' is being sealed.";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 200;
                            break;
                        case CRUST_STORAGE_FILE_DELETING:
                            ret_info = "Same file '" + cid + "' is being deleted.";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 400;
                            break;
                        default:
                            ret_info = "Seal file '" + cid + "' failed! Unexpected error, error code:" + num_to_hexstring(crust_status);
                            p_log->err("%s\n", ret_info.c_str());
                            ret_code = 500;
                    }
                }
                else
                {
                    ret_info = "Ready for sealing file '" + cid + "', waiting for file block";
                    p_log->info("%s\n", ret_info.c_str());
                    ret_code = 200;
                }
            }
            ret_body[HTTP_STATUS_CODE] = std::stoi(num_to_hexstring(crust_status), NULL, 10);
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_code);
            res.body() = ret_body.dump();

            goto postcleanup;
        }

        // ----- Seal file ----- //
        cur_path = urlendpoint.base + "/storage/seal";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            crust_status_t crust_status = CRUST_SUCCESS;

            // Parse paramters
            std::string cid = params_m["cid"];
            bool is_link = (params_m["new_block"] == "true");
            std::vector<uint8_t> body_vec = req.body();
            const uint8_t *sealed_data = (const uint8_t *)body_vec.data();
            size_t sealed_data_sz = body_vec.size();
            //p_log->info("Dealing with seal request(file cid:'%s')...\n", cid.c_str());

            
            sgx_status_t sgx_status = SGX_SUCCESS;
            char *index_path = (char *)malloc(IPFS_INDEX_LENGTH);
            memset(index_path, 0, IPFS_INDEX_LENGTH);
            if (SGX_SUCCESS != (sgx_status = Ecall_seal_file(global_eid, &crust_status, cid.c_str(), sealed_data, sealed_data_sz, is_link, index_path, IPFS_INDEX_LENGTH)))
            {
                ret_info = "Seal file '%s' failed! Invoke SGX API failed! Error code:" + num_to_hexstring(sgx_status);
                p_log->err("%s\n", ret_info.c_str());
                ret_code = 500;
            }
            else if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                    case CRUST_SEAL_DATA_FAILED:
                        ret_info = "Seal file '" + cid + "' failed! Internal error: seal data failed";
                        p_log->err("%s\n", ret_info.c_str());
                        ret_code = 500;
                        break;
                    case CRUST_UPGRADE_IS_UPGRADING:
                        ret_info = "Seal file '" + cid + "' stopped due to upgrading or exiting";
                        p_log->info("%s\n", ret_info.c_str());
                        ret_code = 503;
                        break;
                    case CRUST_STORAGE_NEW_FILE_NOTFOUND:
                        ret_info = "Seal file '" + cid + "' failed, no request or file has been removed";
                        p_log->debug("%s\n", ret_info.c_str());
                        ret_code = 500;
                        break;
                    case CRUST_STORAGE_NO_ENOUGH_SPACE:
                        ret_info = "Seal file '" + cid + "' failed, no enough space";
                        p_log->err("%s\n", ret_info.c_str());
                        ret_code = 500;
                        break;
                    default:
                        ret_info = "Seal file '" + cid + "' failed! Unexpected error, error code:" + num_to_hexstring(crust_status);
                        p_log->err("%s\n", ret_info.c_str());
                        ret_code = 500;
                }
            }
            else
            {
                ret_info = "Seal file '" + cid + "' successfully";
                //p_log->info("%s\n", ret_info.c_str());
                ret_code = 200;
                ret_body[HTTP_IPFS_INDEX_PATH] = std::string(index_path);
            }
            free(index_path);
            
            ret_body[HTTP_STATUS_CODE] = std::stoi(num_to_hexstring(crust_status), NULL, 10);
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_code);
            res.body() = ret_body.dump();

            goto postcleanup;
        }

        // ----- Seal file end ----- //
        cur_path = urlendpoint.base + "/storage/seal_end";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            crust_status_t crust_status = CRUST_SUCCESS;
            sgx_status_t sgx_status = SGX_SUCCESS;
            // Delete file
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_name = "cid";
            if (!req_json.hasKey(param_name) || req_json[param_name].JSONType() != json::JSON::Class::String)
            {
                ret_info = "Bad parameter! Need a string type parameter:'" + param_name + "'";
                ret_code = 400;
            }
            else
            {
                std::string cid = req_json[param_name].ToString();
                if (SGX_SUCCESS != (sgx_status = Ecall_seal_file_end(global_eid, &crust_status, cid.c_str())))
                {
                    ret_info = "Start seal file '%s' failed! Invoke SGX API failed! Error code:" + num_to_hexstring(sgx_status);
                    p_log->err("%s\n", ret_info.c_str());
                    ret_code = 500;
                }
                else if (CRUST_SUCCESS != crust_status)
                {
                    switch (crust_status)
                    {
                        case CRUST_UPGRADE_IS_UPGRADING:
                            ret_info = "Seal file '" + cid + "' stopped due to upgrading or exiting";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 503;
                            break;
                        case CRUST_STORAGE_NEW_FILE_NOTFOUND:
                            ret_info = "File '" + cid + "' is not being sealed";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 404;
                            break;
                        case CRUST_STORAGE_INCOMPLETE_BLOCK:
                            ret_info = "Seal file '" + cid + "' failed due to incomplete file blocks";
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 500;
                            break;
                        default:
                            ret_info = "Seal file '" + cid + "' failed! Error code:" + num_to_hexstring(crust_status);
                            p_log->info("%s\n", ret_info.c_str());
                            ret_code = 500;
                    }
                }
                else
                {
                    ret_info = "Seal file '" + cid + "' successfully";
                    p_log->info("%s\n", ret_info.c_str());
                    ret_code = 200;
                }
            }
            ret_body[HTTP_STATUS_CODE] = std::stoi(num_to_hexstring(crust_status), NULL, 10);
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_code);
            res.body() = ret_body.dump();

            goto postcleanup;
        }

        // ----- Unseal data ----- //
        cur_path = urlendpoint.base + "/storage/unseal";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            std::string ret_info;
            int ret_code = 400;
            //p_log->info("Dealing with unseal request...\n");
            // Parse parameters
            json::JSON req_json = json::JSON::Load_unsafe((const uint8_t *)req.body().data(), req.body().size());
            std::string param_name = "path";
            if (!req_json.hasKey(param_name) || req_json[param_name].JSONType() != json::JSON::Class::String)
            {
                ret_info = "Bad parameter! Need a string type parameter:'" + param_name + "'";
                ret_code = 400;
            }
            else
            {
                std::string index_path = req_json[param_name].ToString();
                // ----- Unseal file ----- //
                crust_status_t crust_status = CRUST_SUCCESS;
                sgx_status_t sgx_status = SGX_SUCCESS;
                if (!is_file_exist(index_path.c_str(), STORE_TYPE_FILE))
                {
                    std::string cid_header = index_path.substr(0, index_path.find_last_of('/'));
                    if (cid_header.size() < UUID_LENGTH * 2)
                    {
                        ret_info = "Malwared index path:" + index_path;
                        ret_code = 404;
                    }
                    else
                    {
                        std::string cid = cid_header.substr(UUID_LENGTH * 2, cid_header.size() - (UUID_LENGTH * 2));
                        std::string type;
                        bool exist = ed->find_file_type(cid, type);
                        if (!exist || (exist && type.compare(FILE_TYPE_PENDING) == 0))
                        {
                            ret_info = "Requested cid:'" + cid + "' is not existed.";
                            ret_code = 404;
                        }
                        else
                        {
                            ret_info = "File block:'" + index_path + "' is lost";
                            ret_code = 410;
                        }
                    }
                    p_log->debug("%s\n", ret_info.c_str());
                }
                else
                {
                    size_t decrypted_data_sz = get_file_size(index_path.c_str(), STORE_TYPE_FILE);
                    uint8_t *p_decrypted_data = (uint8_t *)malloc(decrypted_data_sz);
                    size_t decrypted_data_sz_r = 0;
                    memset(p_decrypted_data, 0, decrypted_data_sz);
                    Defer def_decrypted_data([&p_decrypted_data](void) { free(p_decrypted_data); });
                    if (SGX_SUCCESS != (sgx_status = Ecall_unseal_file(global_eid, &crust_status, index_path.c_str(), p_decrypted_data, decrypted_data_sz, &decrypted_data_sz_r)))
                    {
                        ret_info = "Unseal failed! Invoke SGX API failed! Error code:" + num_to_hexstring(sgx_status);
                        p_log->err("%s\n", ret_info.c_str());
                        ret_code = 500;
                    }
                    else
                    {
                        if (CRUST_SUCCESS == crust_status)
                        {
                            ret_info = "Unseal data successfully!";
                            ret_code = 200;
                            //p_log->info("%s\n", ret_info.c_str());
                            res.body().clear();
                            res.body().append(reinterpret_cast<char *>(p_decrypted_data), decrypted_data_sz_r);
                            res.result(ret_code);
                        }
                        else
                        {
                            switch (crust_status)
                            {
                            case CRUST_UNSEAL_DATA_FAILED:
                                ret_info = "Unseal data failed! SGX unseal data failed!";
                                p_log->err("%s\n", ret_info.c_str());
                                ret_code = 400;
                                break;
                            case CRUST_UPGRADE_IS_UPGRADING:
                                ret_info = "Unseal file stoped due to upgrading or exiting";
                                p_log->info("%s\n", ret_info.c_str());
                                ret_code = 503;
                                break;
                            default:
                                ret_info = "Unseal data failed! Error code:" + num_to_hexstring(crust_status);
                                p_log->err("%s\n", ret_info.c_str());
                                ret_code = 404;
                            }
                        }
                    }
                }
            }
            if (200 != ret_code)
            {
                json::JSON ret_body;
                ret_body[HTTP_STATUS_CODE] = ret_code;
                ret_body[HTTP_MESSAGE] = ret_info;
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
            }

            goto postcleanup;
        }

        // ----- Recover illegal file ----- //
        cur_path = urlendpoint.base + "/file/recover_illegal";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            std::string ret_info;
            int ret_code = 400;
            sgx_status_t sgx_status = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            json::JSON req_json = json::JSON::Load(&crust_status, req.body().data(), req.body().size());
            if (CRUST_SUCCESS != crust_status)
            {
                ret_info = "Invalid parameter! Need a json format parameter like:{\"added_files\":[\"Qmxxx\"],\"deleted_files\":[\"Qmxxx\"]}";
                p_log->err("%s\n", ret_info.c_str());
                ret_code = 400;
            }
            else
            {
                if ((!req_json.hasKey(WORKREPORT_FILES_ADDED) && !req_json.hasKey(WORKREPORT_FILES_DELETED))
                    || (req_json.hasKey(WORKREPORT_FILES_ADDED) && req_json[WORKREPORT_FILES_ADDED].JSONType() != json::JSON::Class::Array)
                    || (req_json.hasKey(WORKREPORT_FILES_DELETED) && req_json[WORKREPORT_FILES_DELETED].JSONType() != json::JSON::Class::Array))
                {
                    ret_info = "Invalid parameter! Need a json format parameter like:{\"added_files\":[\"Qmxxx\"],\"deleted_files\":[\"Qmxxx\"]}";
                    p_log->err("%s\n", ret_info.c_str());
                    ret_code = 400;
                }
                else
                {
                    if (SGX_SUCCESS != (sgx_status = Ecall_recover_illegal_file(global_eid, &crust_status, req.body().data(), req.body().size())))
                    {
                        ret_info = "Recover illegal file failed! Invoke SGX API failed! Error code:" + num_to_hexstring(sgx_status);
                        p_log->err("%s\n", ret_info.c_str());
                        ret_code = 500;
                    }
                    else
                    {
                        if (CRUST_SUCCESS != crust_status)
                        {
                            ret_info = "Unexpected error:" + num_to_hexstring(crust_status);
                            p_log->err("%s\n", ret_info.c_str());
                            ret_code = 500;
                        }
                        else
                        {
                            ret_info = "Recover illegal file done.";
                            p_log->err("%s\n", ret_info.c_str());
                            ret_code = 200;
                        }
                    }
                }
            }
            json::JSON ret_body;
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            std::string ret_str = ret_body.dump();
            remove_char(ret_str, '\\');
            res.body() = ret_str;

            goto postcleanup;
        }


    postcleanup:
        res.content_length(res.body().size());
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }
}

#endif /* !_CRUST_API_HANDLER_H_ */
