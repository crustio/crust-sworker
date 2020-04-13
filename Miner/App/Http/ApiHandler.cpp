#include "ApiHandler.h"
#include "Json.hpp"
#include "sgx_tseal.h"
#include <exception>

using namespace httplib;

extern sgx_enclave_id_t global_eid;

/* Used to show validation status*/
const char *validation_status_strings[] = {"validate_stop", "validate_waiting", "validate_meaningful", "validate_empty"};
bool in_changing_empty = false;
std::mutex change_empty_mutex;
int change_empty_num = 0;

std::map<std::vector<uint8_t>, MerkleTree *> hash_tree_map;
crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: constructor
 */
ApiHandler::ApiHandler()
{
    this->server = new Server();
}

// TODO: Should limit thread number in enclave
/**
 * @desination: Start rest service
 * @return: Start status
 * */
int ApiHandler::start()
{
    Config *p_config = Config::get_instance();
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);

    if (!server->is_valid())
    {
        p_log->err("Server encount an error!\n");
        return -1;
    }

    // Outter APIs
    std::string path = urlendpoint->base + "/status";
    server->Get(path.c_str(), [=](const Request & /*req*/, Response &res) {
        validation_status_t validation_status = VALIDATE_STOP;

        if (ecall_return_validation_status(global_eid, &validation_status) != SGX_SUCCESS)
        {
            p_log->err("Get validation status failed.\n");
            res.set_content("InternalError", "text/plain");
            return;
        }

        res.set_content(std::string("{\"validation_status\":") + "\"" + validation_status_strings[validation_status] + "\"}", "text/plain");
        return;
    });

    path = urlendpoint->base + "/report";
    server->Get(path.c_str(), [=](const Request & /*req*/, Response &res) {
        /* Call ecall function to get work report */
        size_t report_len = 0;
        if (ecall_generate_validation_report(global_eid, &report_len) != SGX_SUCCESS)
        {
            p_log->err("Generate validation report failed.\n");
            res.set_content("InternalError", "text/plain");
        }

        char *report = new char[report_len];
        if (ecall_get_validation_report(global_eid, report, report_len) != SGX_SUCCESS)
        {
            p_log->err("Get validation report failed.\n");
            res.set_content("InternalError", "text/plain");
        }

        if (report == NULL)
        {
            res.set_content("InternalError", "text/plain");
        }

        res.set_content(report, "text/plain");
        delete report;
    });

    // Entry network process
    path = urlendpoint->base + "/entry/network";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        res.status = 200;
        sgx_status_t status_ret = SGX_SUCCESS;
        crust_status_t crust_status = CRUST_SUCCESS;
        int version = IAS_API_DEF_VERSION;
        p_log->info("Processing entry network application...\n");
        uint32_t qsz;
        size_t dqsz = 0;
        sgx_quote_t *quote;
        json::JSON req_json = json::JSON::Load(req.params.find("arg")->second);
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
            res.set_content("InternalError", "text/plain");
            res.status = 400;
            return;
        }

        if (b64quote.size() == 0)
        {
            res.set_content("InternalError", "text/plain");
            res.status = 400;
            return;
        }

        quote = (sgx_quote_t *)malloc(qsz);
        memset(quote, 0, qsz);
        memcpy(quote, base64_decode(b64quote.c_str(), &dqsz), qsz);

        status_ret = ecall_store_quote(global_eid, &crust_status,
                (const char *)quote, qsz, (const uint8_t *)data_sig_str.c_str(),
                data_sig_str.size(), &data_sig, (const uint8_t *)off_chain_chain_account_id.c_str(),
                off_chain_chain_account_id.size());
        if (SGX_SUCCESS != status_ret || CRUST_SUCCESS != crust_status)
        {
            p_log->err("Store and verify offChain node data failed!\n");
            res.set_content("StoreQuoteError", "text/plain");
            res.status = 401;
            return;
        }
        p_log->info("Storing quote in enclave successfully!\n");

        /* Request IAS verification */
        SSLClient *client = new SSLClient(p_config->ias_base_url);
        Headers headers = {
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
            res.set_content("Request IAS failed!", "text/plain");
            res.status = 402;
            delete client;
            return;
        }
        res_json = json::JSON::Load(ias_res->body);
        p_log->info("Sending quote to IAS service successfully!\n");

        Headers res_headers = ias_res->headers;
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

        /* Verify IAS report in enclave */
        entry_network_signature ensig;
        status_ret = ecall_verify_iasreport(global_eid, &crust_status, (const char **)ias_report.data(), ias_report.size(), &ensig);
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
                res.set_content(jsonstr.c_str(), "text/plain");
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
                res.set_content("Verify IAS report failed!", "text/plain");
                res.status = 403;
            }
        }
        else
        {
            p_log->err("Invoke SGX api failed!\n");
            res.set_content("Invoke SGX api failed!", "text/plain");
            res.status = 404;
        }
        delete client;
    });

    // Storage validate merkle tree
    path = urlendpoint->base + "/storage/validate/merkletree";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        res.status = 200;
        //p_log->info("status:%d,validate MerkleTree body:%s\n", res.status, req.body.c_str());
        std::string error_info;
        // Get backup info
        if (req.headers.find("backup") == req.headers.end())
        {
            error_info = "Validate MerkleTree failed!Error: Empty backup!";
            res.status = 400;
        }
        else if (p_config->chain_backup.compare(req.headers.find("backup")->second) != 0)
        {
            error_info = "Validate MerkleTree failed!Error: Invalid backup!";
            res.status = 401;
        }
        if (res.status != 200)
        {
            p_log->err("%s\n", error_info.c_str());
            res.set_content(error_info, "text/plain");
            return;
        }
        // Check if body is validated
        if (req.body.size() == 0)
        {
            error_info = "Validate MerkleTree failed!Error: Empty body!";
            p_log->err("%s\n", error_info.c_str());
            res.set_content(error_info, "text/plain");
            res.status = 402;
            return;
        }

        // Get MerkleTree
        json::JSON req_json;
        try
        {
            req_json = json::JSON::Load(req.body);
        }
        catch (std::exception e)
        {
            p_log->err("Parse json failed!Error: %s\n", e.what());
            res.set_content("Validate MerkleTree failed!Error invalide MerkleTree json!", "text/plain");
            res.status = 403;
            return;
        }
        MerkleTree *root = deserialize_merkle_tree_from_json(req_json);
        if (root == NULL)
        {
            p_log->err("Deserialize MerkleTree failed!\n");
            res.set_content("Deserialize MerkleTree failed!", "text/plain");
            res.status = 404;
            return;
        }

        // Validate MerkleTree
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != ecall_validate_merkle_tree(global_eid, &crust_status, &root) ||
            CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_MERKLETREE_DUPLICATED:
                    error_info = "Duplicated MerkleTree validation!";
                    break;
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
            res.set_content(error_info, "text/plain");
            res.status = 405;
        }
        else
        {
            p_log->info("Validate merkle tree successfully!\n");
            res.set_content("Validate merkle tree successfully!", "text/plain");
        }
    });

    // Storage seal file block
    path = urlendpoint->base + "/storage/seal";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        res.status = 200;
        std::string error_info;
        // Get backup info
        if (req.headers.find("backup") == req.headers.end())
        {
            error_info = "Validate MerkleTree failed!Error: Empty backup!";
            res.status = 400;
        }
        else if (p_config->chain_backup.compare(req.headers.find("backup")->second) != 0)
        {
            error_info = "Validate MerkleTree failed!Error: Invalid backup!";
            res.status = 401;
        }
        if (res.status != 200)
        {
            p_log->err("%s\n", error_info.c_str());
            res.set_content(error_info, "text/plain");
            return;
        }
        // Get source data
        size_t src_len = req.body.size();
        if (src_len == 0)
        {
            res.set_content("Seal data failed!Error empty request body!", "text/plain");
            res.status = 402;
            return;
        }
        std::vector<uint8_t> data_u(req.body.data(), req.body.data() + req.body.size());
        uint8_t *p_src = data_u.data();

        // Get root hash
        std::string root_hash_str = req.params.find("root_hash")->second;
        if (root_hash_str.size() == 0)
        {
            res.set_content("Seal data failed!Error Empty root hash!", "text/plain");
            res.status = 403;
            return;
        }
        uint8_t *root_hash = hex_string_to_bytes(root_hash_str.c_str(), root_hash_str.size());

        // Get sealed data buffer
        size_t sealed_data_size = sizeof(uint32_t) * 2 + src_len + SGX_ECP256_KEY_SIZE;
        size_t sealed_data_size_r = sgx_calc_sealed_data_size(0, sealed_data_size);
        uint8_t *p_sealed_data = (uint8_t *)malloc(sealed_data_size_r);
        memset(p_sealed_data, 0, sealed_data_size_r);

        // Seal data
        std::string content;
        crust_status_t crust_status = CRUST_SUCCESS;
        sgx_status_t sgx_status = ecall_seal_data(global_eid, &crust_status, root_hash, HASH_LENGTH,
                p_src, src_len, p_sealed_data, sealed_data_size_r);

        if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_NOTFOUND_MERKLETREE:
                    error_info = "Given MerkleTree tree root hash is not found!";
                    break;
                case CRUST_WRONG_FILE_BLOCK:
                    error_info = "Given file block doesn't meet sequential request!";
                    break;
                case CRUST_SEAL_DATA_FAILED:
                    error_info = "Internal error: seal data failed!";
                    break;
                default:
                    error_info = "Undefined error!";
                }
            }
            else
            {
                error_info = "Invoke SGX api failed!";
            }
            p_log->info("Seal data failed!Error code:%lx(%s)\n", crust_status, error_info.c_str());
            res.set_content(error_info, "text/plain");
            res.status = 404;
            goto cleanup;
        }

        content = std::string(hexstring(p_sealed_data, sealed_data_size_r), sealed_data_size_r * 2);
        res.set_content(content, "text/plain");
        p_log->info("Seal content:%s\n", content.c_str());

    cleanup:
        free(p_sealed_data);
        free(root_hash);
    });

    // Storage unseal file block
    path = urlendpoint->base + "/storage/unseal";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        res.status = 200;
        std::string error_info;
        // Get backup info
        if (req.headers.find("backup") == req.headers.end())
        {
            error_info = "Validate MerkleTree failed!Error: Empty backup!";
            res.status = 400;
        }
        else if (p_config->chain_backup.compare(req.headers.find("backup")->second) != 0)
        {
            error_info = "Validate MerkleTree failed!Error: Invalid backup!";
            res.status = 401;
        }
        if (res.status != 200)
        {
            p_log->err("%s\n", error_info.c_str());
            res.set_content(error_info, "text/plain");
            return;
        }
        // Get sealed data
        if (req.body.size() == 0)
        {
            res.set_content("Unseal data failed!Error empty data!", "text/plain");
            res.status = 402;
            return;
        }
        std::vector<uint8_t> data_u(req.body.data(), req.body.data() + req.body.size());
        uint8_t *p_sealed_data = data_u.data();
        size_t sealed_data_size = req.body.size();

        // Caculate unsealed data size
        sgx_sealed_data_t *p_sealed_data_r = (sgx_sealed_data_t *)malloc(sealed_data_size);
        memset(p_sealed_data_r, 0, sealed_data_size);
        memcpy(p_sealed_data_r, p_sealed_data, sealed_data_size);
        uint32_t unsealed_data_size = sgx_get_encrypt_txt_len(p_sealed_data_r);
        unsealed_data_size = unsealed_data_size - sizeof(uint32_t) * 2 - SGX_ECP256_KEY_SIZE;
        uint8_t *p_unsealed_data = (uint8_t *)malloc(unsealed_data_size);

        // Unseal data
        std::string content;
        crust_status_t crust_status = CRUST_SUCCESS;
        sgx_status_t sgx_status = ecall_unseal_data(global_eid, &crust_status,
                p_sealed_data, sealed_data_size, p_unsealed_data, unsealed_data_size);

        if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_UNSEAL_DATA_FAILED:
                    error_info = "Internal error: unseal data failed!";
                    break;
                case CRUST_MALWARE_DATA_BLOCK:
                    error_info = "Unsealed data is invalid!";
                    break;
                default:
                    error_info = "Undefined error!";
                }
            }
            else
            {
                error_info = "Invoke SGX api failed!";
            }
            p_log->err("Unseal data failed!Error code:%lx(%s)\n", crust_status, error_info.c_str());
            res.set_content(error_info, "text/plain");
            res.status = 403;
            goto cleanup;
        }

        content = std::string(hexstring(p_unsealed_data, unsealed_data_size), unsealed_data_size * 2);
        p_log->info("Unseal data successfully!\n");
        res.set_content(content, "text/plain");

    cleanup:
        free(p_unsealed_data);
        free(p_sealed_data_r);
    });

    // Storage generate validated merkle tree
    path = urlendpoint->base + "/storage/generate/merkletree";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        res.status = 200;
        std::string error_info;
        // Get backup info
        if (req.headers.find("backup") == req.headers.end())
        {
            error_info = "Validate MerkleTree failed!Error: Empty backup!";
            res.status = 400;
        }
        else if (p_config->chain_backup.compare(req.headers.find("backup")->second) != 0)
        {
            error_info = "Validate MerkleTree failed!Error: Invalid backup!";
            res.status = 401;
        }
        if (res.status != 200)
        {
            p_log->err("%s\n", error_info.c_str());
            res.set_content(error_info, "text/plain");
            return;
        }
        // Get root hash
        std::string root_hash_str = req.params.find("root_hash")->second;
        if (root_hash_str.size() == 0)
        {
            res.set_content("Generate MerkleTree failed!Error empty hash!", "text/plain");
            res.status = 402;
            return;
        }
        uint8_t *root_hash = hex_string_to_bytes(root_hash_str.c_str(), root_hash_str.size());
        p_log->info("root hash:%s\n", root_hash_str.c_str());

        // Generate MerkleTree
        crust_status_t crust_status = CRUST_SUCCESS;
        sgx_status_t sgx_status = ecall_gen_new_merkle_tree(global_eid, &crust_status, root_hash, HASH_LENGTH);
        if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
        {
            if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_NOTFOUND_MERKLETREE:
                    error_info = "Given MerkleTree is not found!";
                    break;
                case CRUST_SEAL_NOTCOMPLETE:
                    error_info = "Not all Given MerkleTree's data blocks have been sealed!";
                    break;
                case CRUST_DESER_MERKLE_TREE_FAILED:
                    error_info = "Internal error: deserialize MerkleTree failed!";
                    break;
                default:
                    error_info = "Undefined error!";
                }
            }
            else
            {
                error_info = "Invoke SGX api failed!";
            }
            p_log->err("Generate new merkle tree failed!Error code:%lx(%s)\n",
                       crust_status, error_info.c_str());
            res.set_content("Generate new merkle tree failed!", "text/plain");
            res.status = 403;
            goto cleanup;
        }

        res.set_content("Generate new merkle tree successfully!", "text/plain");

    cleanup:
        free(root_hash);
    });

    // Inner APIs
    path = urlendpoint->base + "/change/empty";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        res.status = 200;
        std::string error_info;
        // Get backup info
        if (req.headers.find("backup") == req.headers.end())
        {
            error_info = "Validate MerkleTree failed!Error: Empty backup!";
            res.status = 400;
        }
        else if (p_config->chain_backup.compare(req.headers.find("backup")->second) != 0)
        {
            error_info = "Validate MerkleTree failed!Error: Invalid backup!";
            res.status = 401;
        }
        if (res.status != 200)
        {
            p_log->err("%s\n", error_info.c_str());
            res.set_content(error_info, "text/plain");
            return;
        }
        // Guaranteed that only one service is running
        change_empty_mutex.lock();
        if (in_changing_empty)
        {
            p_log->info("Change empty service busy\n");
            res.set_content("Change empty service busy", "text/plain");
            res.status = 500;
            change_empty_mutex.unlock();
            return;
        }
        in_changing_empty = true;
        change_empty_mutex.unlock();

        // Check input parameters
        json::JSON req_json = json::JSON::Load(req.body);
        change_empty_num = req_json["change"].ToInt();

        if (change_empty_num == 0)
        {
            p_log->info("Invalid change\n");
            res.set_content("Invalid change", "text/plain");
            res.status = 402;
            goto end_change_empty;
        }
        else
        {
            // Check TEE has already launched
            validation_status_t validation_status = VALIDATE_STOP;

            if (ecall_return_validation_status(global_eid, &validation_status) != SGX_SUCCESS)
            {
                p_log->info("Get validation status failed.\n");
                res.set_content("Get validation status failed", "text/plain");
                res.status = 500;
                goto end_change_empty;
            }
            else if (validation_status == VALIDATE_STOP)
            {
                p_log->info("TEE has not been fully launched.\n");
                res.set_content("TEE has not been fully launched", "text/plain");
                res.status = 500;
                goto end_change_empty;
            }

            // Start changing empty
            pthread_t wthread;
            if (pthread_create(&wthread, NULL, ApiHandler::change_empty, NULL) != 0)
            {
                p_log->err("Create change empty thread error.\n");
                res.set_content("Create change empty thread error", "text/plain");
                res.status = 500;
                goto end_change_empty;
            }
            else
            {
                res.set_content("Change empty file success, the empty workload will change in next validation loop", "text/plain");
                return;
            }
        }
    end_change_empty:
        change_empty_mutex.lock();
        in_changing_empty = false;
        change_empty_mutex.unlock();
    });

    server->listen(urlendpoint->ip.c_str(), urlendpoint->port);

    return 1;
}

/**
 * @desination: Stop rest service
 * @return: Stop status
 * */
int ApiHandler::stop()
{
    this->server->stop();
    return 1;
}

/**
 * @description: destructor
 */
ApiHandler::~ApiHandler()
{
    delete this->server;
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
