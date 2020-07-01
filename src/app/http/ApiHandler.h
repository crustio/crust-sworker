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
    void change_srd(long change);
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
int change_empty_num = 0;

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
    p_log->debug("Request url:%s\n", path.c_str());
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


        // Outter APIs
        cur_path = urlendpoint->base + "/status";
        if (path.compare(cur_path) == 0)
        {
            validation_status_t validation_status = VALIDATE_STOP;

            if (Ecall_return_validation_status(global_eid, &validation_status) != SGX_SUCCESS)
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
            if (Ecall_generate_work_report(global_eid, &crust_status, &report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
            {
                p_log->err("Generate validation report failed. Error code: %x\n", crust_status);
                res.body() = "InternalError";
                goto getcleanup;
            }

            char *report = (char*)malloc(report_len);
            memset(report, 0, report_len);
            if (Ecall_get_work_report(global_eid, &crust_status, report, report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
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

        cur_path = urlendpoint->base + "/srd/info";
        if (path.compare(cur_path) == 0)
        {
            crust_status_t crust_status = CRUST_SUCCESS;
            crust::DataBase *db = crust::DataBase::get_instance();
            std::string srd_info;
            if (CRUST_SUCCESS != (crust_status = db->get("srd_info", srd_info)))
            {
                p_log->debug("Get srd info failed! Error code:%lx\n", crust_status);
                goto getcleanup;
            }
            res.body() = srd_info;
            goto getcleanup;
        }


        cur_path = urlendpoint->base + "/enclave/thread_info";
        if (path.compare(cur_path) == 0)
        {
            res.body() = show_enclave_thread_info();
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
                change_srd(change_empty_num);
                res.body() = "SRD change has been added!";
            }
        end_change_empty:
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
            if (SGX_SUCCESS != (sgx_status = Ecall_confirm_file(global_eid, hash.c_str())))
            {
                p_log->err("Confirm new file failed!Invoke SGX API failed!Error code:%lx\n", sgx_status);
                res.result(402);
            }
            else
            {
                ret_info = "Confirming new file has beening added!";
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
