#ifndef _CRUST_API_HANDLER_H_
#define _CRUST_API_HANDLER_H_

#include <stdio.h>
#include <algorithm>
#include <mutex>
#include <set>
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
#include "Storage.h"
#include "EnclaveData.h"
#include "Chain.h"
#include "tbb/concurrent_unordered_map.h"
#include "../enclave/include/Parameter.h"

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
    bool unseal_check_backup = false;
    MerkleTree *tree_root = NULL;
};

std::string path_cat(beast::string_view base, beast::string_view path);
std::map<std::string, std::string> get_params(std::string &url);

extern sgx_enclave_id_t global_eid;
extern tbb::concurrent_unordered_map<std::string, std::string> sealed_tree_map;
extern std::mutex srd_info_mutex;
// Used to show validation status
long change_srd_num = 0;

/**
 * @desination: Start rest service
 * @return: Start status
 */
template<class Body, class Allocator, class Send>
void ApiHandler::http_handler(beast::string_view /*doc_root*/,
    http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send, bool /*is_ssl*/)
{
    Config *p_config = Config::get_instance();
    crust::Log *p_log = crust::Log::get_instance();
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->base_url);
    EnclaveData *ed = EnclaveData::get_instance();
    std::string cur_path;
    // Upgrade block service set
    std::set<std::string> upgrade_block_s = {
        "/workload",
        "/srd/change",
        "/storage/confirm",
        "/storage/delete",
        "/storage/seal",
        "/storage/unseal",
    };

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
    std::map<std::string, std::string> params = get_params(path);
    size_t epos = path.find('\?');
    if (epos != std::string::npos)
    {
        path = path.substr(0, epos);
    }

    // Choose service according to upgrade status
    std::string route_tag = path.substr(path.find(urlendpoint->base) + urlendpoint->base.size(), path.size());
    if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status())
    {
        p_log->err("This process will exit!\n");
        http::response<http::string_body> res{
            std::piecewise_construct,
            std::make_tuple("Stop service!"),
            std::make_tuple(http::status::ok, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.body() = "No service will be provided because of upgrade!";
        res.result(503);
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
            std::make_tuple(http::status::ok, req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.body() = "Current service is closed due to upgrade!";
        res.result(503);
        return send(std::move(res));
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
            // Get srd info
            if (SGX_SUCCESS != Ecall_get_workload(global_eid))
            {
                p_log->warn("Get workload failed! Error code:%lx\n", sgx_status);
            }
            json::JSON wl_json = json::JSON::Load(ed->get_enclave_workload());
            if (wl_json.size() == -1)
            {
                res.body() = "Get workload failed!";
                goto getcleanup;
            }
            wl_json["srd"]["disk_reserved"] = get_reserved_space();
            size_t tmp_size = 0;
            size_t srd_space = 0;
            json::JSON disk_json = get_increase_srd_info(tmp_size);
            if (wl_json["srd"]["detail"].JSONType() == json::JSON::Class::Object)
            {
                for (auto it = wl_json["srd"]["detail"].ObjectRange().begin(); 
                        it != wl_json["srd"]["detail"].ObjectRange().end(); it++)
                {
                    srd_space += (it->second)["assigned"].ToInt();
                    (it->second)["available"] = disk_json[it->first]["available"];
                    (it->second)["total"] = disk_json[it->first]["total"];
                    std::string disk_item = (it->second).dump();
                    remove_char(disk_item, '\n');
                    replace(disk_item, "}", "  }");
                    it->second = disk_item;
                }
            }
            wl_json["srd"]["space"] = srd_space;
            // Get file info
            json::JSON file_info = wl_json["files"];
            json::JSON n_file_info;
            char buf[128];
            int space_num = 0;
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

            wl_json["files"] = n_file_info;
            std::string wl_str = wl_json.dump();
            replace(wl_str, "\"{", "{");
            replace(wl_str, ": \" ", ":  ");
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
            json::JSON id_json = json::JSON::Load(ed->get_enclave_id_info());
            id_json["account"] = p_config->chain_address;
            id_json["version"] = VERSION;
            id_json["sworker_version"] = SWORKER_VERSION;
            res.body() = id_json.dump();
            goto getcleanup;
        }

        // ----- Inform upgrade ----- //
        cur_path = urlendpoint->base + "/upgrade/start";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            if (UPGRADE_STATUS_NONE != ed->get_upgrade_status()
                    && UPGRADE_STATUS_STOP_WORKREPORT != ed->get_upgrade_status())
            {
                ret_info = "Another upgrading is still running!";
                res.result(300);
                res.body() = ret_info;
                goto getcleanup;
            }
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
                goto getcleanup;
            }

            // Block current work-report for a while
            ed->set_upgrade_status(UPGRADE_STATUS_STOP_WORKREPORT);

            sgx_status_t sgx_status = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            crust::BlockHeader *block_header = crust::Chain::get_instance()->get_block_header();
            if (block_header == NULL)
            {
                ret_info = "Chain is not running!Get block header failed!";
                res.result(402);
                p_log->err("%s\n", ret_info.c_str());
            }
            else if (SGX_SUCCESS != (sgx_status = Ecall_enable_upgrade(global_eid, &crust_status, block_header->number)))
            {
                ret_info = "Invoke SGX API failed!";
                res.result(403);
                p_log->err("%sError code:%lx\n", ret_info.c_str(), sgx_status);
            }
            else
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    ret_info = "Receive upgrade inform successfully!";
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
                            ret_info = "Block expired!Wait for next era.";
                            res.result(405);
                            break;
                        case CRUST_UPGRADE_NO_VALIDATE:
                            ret_info = "Necessary validation not completed!";
                            res.result(406);
                            break;
                        case CRUST_UPGRADE_RESTART:
                            ret_info = "Cannot report due to restart!Wait for next era.";
                            res.result(407);
                            break;
                        case CRUST_UPGRADE_NO_FILE:
                            ret_info = "Cannot get files for check!Please check karst!";
                            res.result(408);
                            break;
                        default:
                            ret_info = "Unknown error.";
                            res.result(409);
                    }
                }
            }
            res.body() = ret_info;

            goto getcleanup;
        }

        // ----- Get metadata ----- //
        cur_path = urlendpoint->base + "/upgrade/metadata";
        if (path.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            if (UPGRADE_STATUS_COMPLETE != ed->get_upgrade_status())
            {
                ret_info = "Metadata is still collecting!";
                res.result(300);
                res.body() = ret_info;
                goto getcleanup;
            }
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
                goto getcleanup;
            }

            std::string upgrade_data = ed->get_upgrade_data();
            p_log->info("Generate upgrade data:%s\n", upgrade_data.c_str());
            res.body() = upgrade_data;

            goto getcleanup;
        }

        // ----- Inform that new version is already ----- //
        // Use to inform current sworker upgrade result
        cur_path = urlendpoint->base + "/upgrade/complete";
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
                goto getcleanup;
            }

            json::JSON req_json = json::JSON::Load(req.body());
            bool upgrade_ret = req_json["success"].ToBool();
            if (!upgrade_ret)
            {
                p_log->err("Upgrade failed!Current version will restore work.\n");
                ed->set_upgrade_status(UPGRADE_STATUS_NONE);
            }
            else
            {
                // Store old metadata to ID_METADATA_OLD
                crust::DataBase *db = crust::DataBase::get_instance();
                crust_status_t crust_status = CRUST_SUCCESS;
                std::string metadata_old;
                if (CRUST_SUCCESS != (crust_status = db->get(ID_METADATA, metadata_old)))
                {
                    p_log->warn("Upgrade: get old metadata failed!Status code:%lx\n", crust_status);
                }
                else
                {
                    if (CRUST_SUCCESS != (crust_status = db->set(ID_METADATA_OLD, metadata_old)))
                    {
                        p_log->warn("Upgrade: store old metadata failed!Status code:%lx\n", crust_status);
                    }
                }
                if (CRUST_SUCCESS != (crust_status = db->del(ID_METADATA)))
                {
                    p_log->warn("Upgrade: delete old metadata failed!Status code:%lx\n", crust_status);
                }
                else
                {
                    p_log->info("Upgrade: clean old version's data successfully!\n");
                }
                // Set upgrade exit flag
                ed->set_upgrade_status(UPGRADE_STATUS_EXIT);
            }

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


        // ----- Set debug flag ----- //
        cur_path = urlendpoint->base + "/debug";
        if (path.compare(cur_path) == 0)
        {
            // Check input parameters
            std::string ret_info;
            json::JSON req_json = json::JSON::Load(req.body());
            if (!req_json.hasKey("debug") || req_json["debug"].JSONType() != json::JSON::Class::Boolean)
            {
                ret_info = "Wrong request body!";
                p_log->err("%s\n", ret_info.c_str());
                res.result(400);
                res.body() = ret_info;
                goto postcleanup;
            }
            bool debug_flag = req_json["debug"].ToBool();
            p_log->set_debug(debug_flag);
            ret_info = "Set debug flag successfully!";
            p_log->info("%s %s debug.\n", ret_info.c_str(), debug_flag ? "Open" : "Close");
            res.result(200);
            res.body() = ret_info;
        }

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
            change_srd_num = req_json["change"].ToInt();

            if (change_srd_num == 0)
            {
                p_log->info("Invalid change\n");
                res.body() = "Invalid change";
                res.result(402);
                goto end_change_srd;
            }
            else
            {
                // Start changing srd
                Ecall_srd_set_change(global_eid, change_srd_num);
                p_log->info("Change task:%ldG has been added, will be executed next srd.\n", change_srd_num);
                res.body() = "Change srd file success, the srd workload will change in next validation loop!";
            }
        end_change_srd:
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
            storage_add_confirm(hash);
            ret_info = "Confirming new file task has beening added!";
            res.body() = ret_info;

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
            storage_add_delete(hash);
            ret_info = "Deleting file task has beening added!";
            res.body() = ret_info;

            goto postcleanup;
        }

        // ----- Storage seal file block ----- //
        cur_path = urlendpoint->base + "/storage/seal";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
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

            crust_status_t crust_status = CRUST_SUCCESS;
            sgx_status_t sgx_status = SGX_SUCCESS;

            p_log->info("Dealing with seal request...\n");

            // Parse paramters
            json::JSON req_json = json::JSON::Load(req.body());
            json::JSON tree_json = req_json["body"];
            std::string dir_path = req_json["path"].ToString();

            // Check if body is validated
            if (tree_json.size() == 0 || tree_json.size() == -1)
            {
                ret_info = "Validate MerkleTree failed!Error: Empty body!";
                p_log->err("%s\n", ret_info.c_str());
                res.body() = ret_info;
                res.result(402);
                goto postcleanup;
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
                        ret_info = "Internal error: seal data failed!";
                        break;
                    case CRUST_STORAGE_FILE_NOTFOUND:
                        ret_info = "Given file cannot be found!";
                        break;
                    case CRUST_FILE_NUMBER_EXCEED:
                        ret_info = "No more file can be sealed!File number reachs the upper limit!";
                        break;
                    default:
                        ret_info = "Unexpected error!";
                    }
                }
                else
                {
                    ret_info = "Invoke SGX api failed!";
                }
                p_log->err("Seal data failed!Error code:%lx(%s)\n", crust_status, ret_info.c_str());
                res.body() = ret_info;
                res.result(403);
            }
            else
            {
                p_log->info("Seal file successfully!\n");

                std::string new_tree_str = sealed_tree_map[org_root_hash_str];
                remove_char(new_tree_str, ' ');
                remove_char(new_tree_str, '\n');
                remove_char(new_tree_str, '\\');
                json::JSON ret_json;
                ret_json["body"] = new_tree_str;
                ret_json["path"] = std::string(p_new_path, dir_path.size());
                res.body() = ret_json.dump();
                res.result(200);
                sealed_tree_map.unsafe_erase(org_root_hash_str);
            }

            if (p_new_path != NULL)
            {
                free(p_new_path);
            }

            goto postcleanup;
        }

        // ----- Storage unseal file block ----- //
        cur_path = urlendpoint->base + "/storage/unseal";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
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

            p_log->info("Dealing with unseal request...\n");
            // Parse parameters
            json::JSON req_json;
            req_json = json::JSON::Load(req.body());
            std::string dir_path = req_json["path"].ToString();

            // Get sub files' path
            std::vector<std::string> files_str = get_sub_folders_and_files(dir_path.c_str());
            std::vector<const char *> sub_files;
            for (size_t i = 0; i < files_str.size(); i++)
            {
                sub_files.push_back(files_str[i].c_str());
            }
            if (sub_files.size() == 0)
            {
                ret_info = "Empty data directory!";
                p_log->err("%s\n", ret_info.c_str());
                res.result(402);
                res.body() = ret_info;
                goto postcleanup;
            }

            // ----- Unseal file ----- //
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
                        ret_info = "Internal error: unseal data failed!";
                        break;
                    case CRUST_STORAGE_UPDATE_FILE_FAILED:
                        ret_info = "Update new file failed!";
                        break;
                    case CRUST_STORAGE_FILE_NOTFOUND:
                        ret_info = "Given file cannot be found!";
                        break;
                    default:
                        ret_info = "Unexpected error!";
                    }
                }
                else
                {
                    ret_info = "Invoke SGX api failed!";
                }
                p_log->err("Unseal data failed!Error code:%lx(%s)\n", crust_status, ret_info.c_str());
                res.body() = ret_info;
                res.result(403);
            }
            else
            {
                p_log->info("Unseal data successfully!\n");
                res.body() = std::string(p_new_path, dir_path.size());
                res.result(200);
            }

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
