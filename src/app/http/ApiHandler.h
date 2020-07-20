#ifndef _CRUST_API_HANDLER_H_
#define _CRUST_API_HANDLER_H_

#include <stdio.h>
#include <algorithm>
#include <mutex>
#include <exception>
#include <sgx_report.h>
#include <sgx_key_exchange.h>
#include <sgx_error.h>
#include "ECalls.h"
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
#include "DataBase.h"
#include "Srd.h"
#include "Data.h"

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
    std::shared_ptr<WebServer> server = NULL;
    std::vector<uint8_t> root_hash_v;
    long block_left_num;
    long block_num;
    bool unseal_check_backup = false;
    MerkleTree *tree_root = NULL;
};

std::string path_cat(beast::string_view base, beast::string_view path);
std::map<std::string, std::string> get_params(std::string &url);

extern sgx_enclave_id_t global_eid;
// Used to show validation status
const char *validation_status_strings[] = {"validate_stop", "validate_waiting", "validate_meaningful", "validate_empty"};
long change_empty_num = 0;

/**
 * @desination: Start rest service
 * @return: Start status
 * */
template<class Body, class Allocator, class Send>
void ApiHandler::http_handler(beast::string_view /*doc_root*/,
    http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, bool /*is_ssl*/)
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
    p_log->info("Request url:%s\n", path.c_str());
    std::map<std::string, std::string> params = get_params(path);
    size_t epos = path.find('\?');
    if (epos != std::string::npos)
    {
        path = path.substr(0, epos);
    }


    // ----- Respond to HEAD request ----- //
    if(req.method() == http::verb::head)
    {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        //res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }


    // ----- Respond to GET request ----- //
    if(req.method() == http::verb::get)
    {
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("crust return"),
            std::make_tuple(http::status::ok, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");


        // ----- Get workload ----- //
        cur_path = urlendpoint->base + "/workload";
        if (path.compare(cur_path) == 0)
        {
            sgx_status_t sgx_status = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            crust::DataBase *db = crust::DataBase::get_instance();
            // Get srd info
            std::string srd_detail;
            if (CRUST_SUCCESS != (crust_status = db->get("srd_info", srd_detail)))
            {
                p_log->warn("Srd info not found!Get workload srd info failed!\n");
            }
            if (SGX_SUCCESS != Ecall_get_workload(global_eid))
            {
                p_log->warn("Get workload failed! Error code:%lx\n", sgx_status);
            }
            json::JSON wl_json = json::JSON::Load(get_g_enclave_workload());
            if (wl_json.size() == -1)
            {
                res.body() = "Get workload failed!";
                goto getcleanup;
            }
            wl_json["srd"]["detail"] = json::JSON::Load(srd_detail);
            wl_json["srd"]["disk_reserved"] = get_reserved_space();
            size_t tmp_size = 0;
            json::JSON disk_json = get_increase_srd_info(tmp_size);
            if (wl_json["srd"]["detail"].JSONType() == json::JSON::Class::Object)
            {
                for (auto it = wl_json["srd"]["detail"].ObjectRange().begin(); 
                        it != wl_json["srd"]["detail"].ObjectRange().end(); it++)
                {
                    (it->second)["available"] = disk_json[it->first]["available"];
                    (it->second)["total"] = disk_json[it->first]["total"];
                    std::string disk_item = (it->second).dump();
                    remove_char(disk_item, '\n');
                    it->second = disk_item;
                }
            }
            // Get file info
            json::JSON files_json = wl_json["files"];
            json::JSON n_files_json;
            if (files_json.JSONType() == json::JSON::Class::Object)
            {
                char buf1[128];
                char buf2[128];
                for (auto it = files_json.ObjectRange().begin(); it != files_json.ObjectRange().end(); it++)
                {
                    std::string item_str = it->second.ToString();
                    remove_char(item_str, '\\');
                    json::JSON item_json = json::JSON::Load(item_str);
                    memset(buf1, 0, sizeof(buf1));
                    memset(buf2, 0, sizeof(buf2));
                    sprintf(buf1, "{  \"hash\"        : \"%s\", \"size\"        : %ld, ",
                            item_json["old_hash"].ToString().c_str(), item_json["old_size"].ToInt());
                    sprintf(buf2, "   \"sealed_hash\" : \"%s\", \"sealed_size\" : %ld  }",
                            (it->first).c_str(), item_json["sealed_size"].ToInt());
                    std::string tmp_str = std::string(buf1) + JSON_NL + std::string(buf2);
                    std::string fstatus = item_json["status"].ToString();
                    n_files_json[fstatus]["detail"].append(tmp_str);
                    n_files_json[fstatus]["number"] = n_files_json[fstatus]["number"].ToInt() + 1;
                }
            }
            wl_json["files"] = n_files_json;
            std::string wl_str = wl_json.dump();
            replace(wl_str, "\"{", "{");
            replace(wl_str, "}\"", "}");
            remove_char(wl_str, '\\');
            res.body() = wl_str;
            goto getcleanup;
        }

        // ----- Get enclave thread information ----- //
        cur_path = urlendpoint->base + "/enclave/thread_info";
        if (path.compare(cur_path) == 0)
        {
            res.body() = show_enclave_thread_info();
            goto getcleanup;
        }

        // ----- Get enclave id information ----- //
        cur_path = urlendpoint->base + "/enclave/id_info";
        if (path.compare(cur_path) == 0)
        {
            Ecall_id_get_info(global_eid);
            res.body() = get_g_enclave_id_info();
            goto getcleanup;
        }


    getcleanup:

        res.content_length(res.body().size());
        //res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }


    // ----- Respond to POST request ----- //
    if(req.method() == http::verb::post)
    {
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("crust return"),
            std::make_tuple(http::status::ok, req.version())};
        res.result(400);
        res.body() = "Unknown request!";
        json::JSON res_json;


        // --- Srd change API --- //
        cur_path = urlendpoint->base + "/srd/change";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            // Get backup info
            if (req.find("backup") == req.end())
            {
                ret_info = "Validate MerkleTree failed!Error: Empty backup!";
                res.result(400);
            }
            else if (p_config->chain_backup.compare(std::string(req.at("backup"))) != 0)
            {
                ret_info = "Validate MerkleTree failed!Error: Invalid backup!";
                res.result(401);
            }
            if (int(res.result()) != 200)
            {
                p_log->err("%s\n", ret_info.c_str());
                res.body() = ret_info;
                goto postcleanup;
            }

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
                // Start changing empty
                Ecall_srd_set_change(global_eid, change_empty_num);
                p_log->info("Change task:%ldG has been added, will be executed next srd.\n", change_empty_num);
                res.body() = "Change srd file success, the srd workload will change in next validation loop!";
            }
        end_change_empty:
            goto postcleanup;
        }

        // --- Change srd reserved space --- //
        cur_path = urlendpoint->base + "/srd/reset";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            // Get backup info
            if (req.find("backup") == req.end())
            {
                ret_info = "Validate MerkleTree failed!Error: Empty backup!";
                res.result(400);
            }
            else if (p_config->chain_backup.compare(std::string(req.at("backup"))) != 0)
            {
                ret_info = "Validate MerkleTree failed!Error: Invalid backup!";
                res.result(401);
            }
            if (int(res.result()) != 200)
            {
                p_log->err("%s\n", ret_info.c_str());
                res.body() = ret_info;
                goto postcleanup;
            }

            // Change srd reserved
            set_reserved_space(DEFAULT_SRD_RESERVED);
            ret_info = "Stop srd successfully!Set srd reserved space to " + std::to_string(DEFAULT_SRD_RESERVED);
            p_log->info("%s\n", ret_info.c_str());
            res.body() = ret_info;

            goto postcleanup;
        }

        // --- Confirm new file --- //
        cur_path = urlendpoint->base + "/storage/confirm";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            // Get backup info
            if (req.find("backup") == req.end())
            {
                ret_info = "Validate MerkleTree failed!Error: Empty backup!";
                res.result(400);
            }
            else if (p_config->chain_backup.compare(std::string(req.at("backup"))) != 0)
            {
                ret_info = "Validate MerkleTree failed!Error: Invalid backup!";
                res.result(401);
            }
            if (int(res.result()) != 200)
            {
                p_log->err("%s\n", ret_info.c_str());
                res.body() = ret_info;
                goto postcleanup;
            }

            // Confirm new file
            sgx_status_t sgx_status = SGX_SUCCESS;
            json::JSON req_json = json::JSON::Load(req.body());
            std::string hash = req_json["hash"].ToString();
            // Check hash
            if (hash.size() != HASH_LENGTH * 2)
            {
                ret_info = "Confirm new file failed!Invalid hash!";
                p_log->err("%s\n", ret_info.c_str());
                res.result(402);
                res.body() = ret_info;
                goto postcleanup;
            }
            if (SGX_SUCCESS != (sgx_status = Ecall_confirm_file(global_eid, hash.c_str())))
            {
                ret_info = "Confirm new file failed!Invoke SGX API failed!";
                p_log->err("%sError code:%lx\n", ret_info.c_str(), sgx_status);
                res.body() = ret_info;
                res.result(403);
            }
            else
            {
                ret_info = "Confirming new file task has beening added!";
                res.body() = ret_info;
            }

            goto postcleanup;
        }

        // --- Delete meaningful file --- //
        cur_path = urlendpoint->base + "/storage/delete";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            // Get backup info
            if (req.find("backup") == req.end())
            {
                ret_info = "Validate MerkleTree failed!Error: Empty backup!";
                res.result(400);
            }
            else if (p_config->chain_backup.compare(std::string(req.at("backup"))) != 0)
            {
                ret_info = "Validate MerkleTree failed!Error: Invalid backup!";
                res.result(401);
            }
            if (int(res.result()) != 200)
            {
                p_log->err("%s\n", ret_info.c_str());
                res.body() = ret_info;
                goto postcleanup;
            }

            // Delete file
            sgx_status_t sgx_status = SGX_SUCCESS;
            json::JSON req_json = json::JSON::Load(req.body());
            std::string hash = req_json["hash"].ToString();
            // Check hash
            if (hash.size() != HASH_LENGTH * 2)
            {
                ret_info = "Delete file failed!Invalid hash!";
                p_log->err("%s\n", ret_info.c_str());
                res.result(402);
                res.body() = ret_info;
                goto postcleanup;
            }
            if (SGX_SUCCESS != (sgx_status = Ecall_delete_file(global_eid, hash.c_str())))
            {
                ret_info = "Delete file failed!Invoke SGX API failed!";
                p_log->err("%sError code:%lx\n", ret_info.c_str(), sgx_status);
                res.body() = ret_info;
                res.result(403);
            }
            else
            {
                ret_info = "Deleting file task has beening added!";
                res.body() = ret_info;
            }

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
