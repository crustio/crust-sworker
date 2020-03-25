#include "ApiHandler.h"
#include "Json.hpp"

using namespace httplib;

/* Used to show validation status*/
const char *validation_status_strings[] = {"ValidateStop", "ValidateWaiting", "ValidateMeaningful", "ValidateEmpty"};
extern FILE *felog;
bool in_changing_empty = false;
std::mutex change_empty_mutex;
int change_empty_num = 0;

sgx_enclave_id_t *ApiHandler::p_global_eid = NULL;

/**
 * @description: constructor
 * @param url -> API base url 
 * @param p_global_eid The point for sgx global eid  
 */
ApiHandler::ApiHandler(sgx_enclave_id_t *p_global_eid_in)
{
    this->server = new Server();
    ApiHandler::p_global_eid = p_global_eid_in;
}

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
        cprintf_err(felog, "Server encount an error!\n");
        return -1;
    }

    // Outter APIs
    std::string path = urlendpoint->base + "/status";
    server->Get(path.c_str(), [=](const Request & /*req*/, Response &res) {
        enum ValidationStatus validation_status = ValidateStop;

        if (ecall_return_validation_status(*ApiHandler::p_global_eid, &validation_status) != SGX_SUCCESS)
        {
            cprintf_err(felog, "Get validation status failed.\n");
            res.set_content("InternalError", "text/plain");
            return;
        }

        res.set_content(std::string("{'validationStatus':") + validation_status_strings[validation_status] + "}", "text/plain");
        return;
    });

    path = urlendpoint->base + "/report";
    server->Get(path.c_str(), [=](const Request & /*req*/, Response &res) {
        /* Call ecall function to get work report */
        size_t report_len = 0;
        if (ecall_generate_validation_report(*ApiHandler::p_global_eid, &report_len) != SGX_SUCCESS)
        {
            cprintf_err(felog, "Generate validation report failed.\n");
            res.set_content("InternalError", "text/plain");
        }

        char *report = new char[report_len];
        if (ecall_get_validation_report(*ApiHandler::p_global_eid, report, report_len) != SGX_SUCCESS)
        {
            cprintf_err(felog, "Get validation report failed.\n");
            res.set_content("InternalError", "text/plain");
        }

        if (report == NULL)
        {
            res.set_content("InternalError", "text/plain");
        }

        res.set_content(report, "text/plain");
        delete report;
    });

    path = urlendpoint->base + "/entry/network";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        sgx_status_t status_ret = SGX_SUCCESS;
        common_status_t common_status = CRUST_SUCCESS;
        int version = IAS_API_DEF_VERSION;
        cprintf_info(felog, "Processing entry network application...\n");
        uint32_t qsz;
        size_t dqsz = 0;
        sgx_quote_t *quote;
        json::JSON req_json = json::JSON::Load(req.params.find("arg")->second);
        std::string b64quote = req_json["isvEnclaveQuote"].ToString();
        std::string off_chain_crust_address = req_json["crust_address"].ToString();
        std::string off_chain_crust_account_id = req_json["crust_account_id"].ToString();
        std::string signature_str = req_json["signature"].ToString();
        std::string data_sig_str;
        data_sig_str.append(b64quote)
            .append(off_chain_crust_address)
            .append(off_chain_crust_account_id);
        sgx_ec256_signature_t data_sig;
        memset(&data_sig, 0, sizeof(sgx_ec256_signature_t));
        memcpy(&data_sig, hex_string_to_bytes(signature_str.c_str(), signature_str.size()),
               sizeof(sgx_ec256_signature_t));

        if (!get_quote_size(&status_ret, &qsz))
        {
            cprintf_err(felog, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
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

        status_ret = ecall_store_quote(*ApiHandler::p_global_eid, &common_status,
                                       (const char *)quote, qsz, (const uint8_t *)data_sig_str.c_str(),
                                       data_sig_str.size(), &data_sig);
        if (SGX_SUCCESS != status_ret || CRUST_SUCCESS != common_status)
        {
            cprintf_err(felog, "Store and verify offChain node data failed!\n");
            res.set_content("StoreQuoteError", "text/plain");
            res.status = 401;
            return;
        }
        cprintf_info(felog, "Storing quote in enclave successfully!\n");

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
                cprintf_err(felog, "Send to IAS failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
                sleep(3);
                net_tryout--;
                continue;
            }
            break;
        }

        if (!(ias_res && ias_res->status == 200))
        {
            cprintf_err(felog, "Request IAS failed!\n");
            res.set_content("Request IAS failed!", "text/plain");
            res.status = 402;
            delete client;
            return;
        }
        res_json = json::JSON::Load(ias_res->body);
        cprintf_info(felog, "Sending quote to IAS service successfully!\n");

        Headers res_headers = ias_res->headers;
        std::vector<const char *> ias_report;
        ias_report.push_back(res_headers.find("X-IASReport-Signing-Certificate")->second.c_str());
        ias_report.push_back(res_headers.find("X-IASReport-Signature")->second.c_str());
        ias_report.push_back(ias_res->body.c_str());

        // Identity info
        ias_report.push_back(off_chain_crust_account_id.c_str()); //[3]
        ias_report.push_back(p_config->crust_account_id.c_str()); //[4]

        // Print IAS report
        if (p_config->verbose)
        {
            cprintf_info(felog, "\n\n----------IAS Report - JSON - Required Fields----------\n\n");
            if (version >= 3)
            {
                fprintf(felog, "version               = %ld\n",
                        res_json["version"].ToInt());
            }
            cprintf_info(felog, "id:                   = %s\n",
                         res_json["id"].ToString().c_str());
            cprintf_info(felog, "timestamp             = %s\n",
                         res_json["timestamp"].ToString().c_str());
            cprintf_info(felog, "isvEnclaveQuoteStatus = %s\n",
                         res_json["isvEnclaveQuoteStatus"].ToString().c_str());
            cprintf_info(felog, "isvEnclaveQuoteBody   = %s\n",
                         res_json["isvEnclaveQuoteBody"].ToString().c_str());
            std::string iasQuoteStr = res_json["isvEnclaveQuoteBody"].ToString();
            size_t qs;
            char *ppp = base64_decode(iasQuoteStr.c_str(), &qs);
            sgx_quote_t *ias_quote = (sgx_quote_t *)malloc(qs);
            memset(ias_quote, 0, qs);
            memcpy(ias_quote, ppp, qs);
            cprintf_info(felog, "========== ias quote report data:%s\n", hexstring(ias_quote->report_body.report_data.d, sizeof(ias_quote->report_body.report_data.d)));
            cprintf_info(felog, "ias quote report version:%d\n", ias_quote->version);
            cprintf_info(felog, "ias quote report signtype:%d\n", ias_quote->sign_type);
            cprintf_info(felog, "ias quote report basename:%s\n", hexstring(&ias_quote->basename, sizeof(sgx_basename_t)));
            cprintf_info(felog, "ias quote report mr_enclave:%s\n", hexstring(&ias_quote->report_body.mr_enclave, sizeof(sgx_measurement_t)));

            cprintf_info(felog, "\n\n----------IAS Report - JSON - Optional Fields----------\n\n");

            cprintf_info(felog, "platformInfoBlob  = %s\n",
                         res_json["platformInfoBlob"].ToString().c_str());
            cprintf_info(felog, "revocationReason  = %s\n",
                         res_json["revocationReason"].ToString().c_str());
            cprintf_info(felog, "pseManifestStatus = %s\n",
                         res_json["pseManifestStatus"].ToString().c_str());
            cprintf_info(felog, "pseManifestHash   = %s\n",
                         res_json["pseManifestHash"].ToString().c_str());
            cprintf_info(felog, "nonce             = %s\n",
                         res_json["nonce"].ToString().c_str());
            cprintf_info(felog, "epidPseudonym     = %s\n",
                         res_json["epidPseudonym"].ToString().c_str());
        }

        /* Verify IAS report in enclave */
        ias_status_t ias_status_ret;
        entry_network_signature ensig;
        status_ret = ecall_verify_iasreport(*ApiHandler::p_global_eid, &ias_status_ret, (const char **)ias_report.data(), ias_report.size(), &ensig);
        if (SGX_SUCCESS == status_ret)
        {
            if (ias_status_ret == IAS_VERIFY_SUCCESS)
            {
                json::JSON identity_json;
                identity_json["pub_key"] = hexstring((const char *)&ensig.pub_key, sizeof(ensig.pub_key));
                identity_json["account_id"] = off_chain_crust_address;
                identity_json["validator_pub_key"] = hexstring((const char *)&ensig.validator_pub_key, sizeof(ensig.validator_pub_key));
                identity_json["validator_account_id"] = p_config->crust_address;
                identity_json["sig"] = hexstring((const char *)&ensig.signature, sizeof(ensig.signature));
                std::string jsonstr = identity_json.dump();
                // Delete space
                jsonstr.erase(std::remove(jsonstr.begin(), jsonstr.end(), ' '), jsonstr.end());
                // Delete line break
                jsonstr.erase(std::remove(jsonstr.begin(), jsonstr.end(), '\n'), jsonstr.end());

                cprintf_info(felog, "Verify IAS report in enclave successfully!\n");
                res.set_content(jsonstr.c_str(), "text/plain");
            }
            else
            {
                switch (ias_status_ret)
                {
                case IAS_BADREQUEST:
                    cprintf_err(felog, "Verify IAS report failed! Bad request!!\n");
                    break;
                case IAS_UNAUTHORIZED:
                    cprintf_err(felog, "Verify IAS report failed! Unauthorized!!\n");
                    break;
                case IAS_NOT_FOUND:
                    cprintf_err(felog, "Verify IAS report failed! Not found!!\n");
                    break;
                case IAS_SERVER_ERR:
                    cprintf_err(felog, "Verify IAS report failed! Server error!!\n");
                    break;
                case IAS_UNAVAILABLE:
                    cprintf_err(felog, "Verify IAS report failed! Unavailable!!\n");
                    break;
                case IAS_INTERNAL_ERROR:
                    cprintf_err(felog, "Verify IAS report failed! Internal error!!\n");
                    break;
                case IAS_BAD_CERTIFICATE:
                    cprintf_err(felog, "Verify IAS report failed! Bad certificate!!\n");
                    break;
                case IAS_BAD_SIGNATURE:
                    cprintf_err(felog, "Verify IAS report failed! Bad signature!!\n");
                    break;
                case IAS_REPORTDATA_NE:
                    cprintf_err(felog, "Verify IAS report failed! Report data not equal!!\n");
                    break;
                case IAS_GET_REPORT_FAILED:
                    cprintf_err(felog, "Verify IAS report failed! Get report in current enclave failed!!\n");
                    break;
                case IAS_BADMEASUREMENT:
                    cprintf_err(felog, "Verify IAS report failed! Bad enclave code measurement!!\n");
                    break;
                case IAS_GETPUBKEY_FAILED:
                    cprintf_err(felog, "Verify IAS report failed! Get public key from certificate failed!!\n");
                    break;
                case CRUST_SIGN_PUBKEY_FAILED:
                    cprintf_err(felog, "Sign public key failed!!\n");
                    break;
                default:
                    cprintf_err(felog, "Unknow return status!\n");
                }
                res.set_content("Verify IAS report failed!", "text/plain");
                res.status = 403;
            }
        }
        else
        {
            cprintf_err(felog, "Invoke SGX api failed!\n");
            res.set_content("Invoke SGX api failed!", "text/plain");
            res.status = 404;
        }
        delete client;
    });

    // Inner APIs
    path = urlendpoint->base + "/change/empty";
    server->Post(path.c_str(), [&](const Request &req, Response &res) {
        // Guaranteed that only one service is running
        change_empty_mutex.lock();
        if (in_changing_empty)
        {
            cprintf_err(felog, "Change empty service busy\n");
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
        std::string backup = req_json["backup"].ToString();
        remove_chars_from_string(backup, "\\");

        if (backup != p_config->crust_backup)
        {
            cprintf_err(felog, "Invalid backup\n");
            res.set_content("Invalid backup", "text/plain");
            res.status = 400;
            goto end_change_empty;
        }

        if (change_empty_num == 0)
        {
            cprintf_err(felog, "Invalid change\n");
            res.set_content("Invalid change", "text/plain");
            res.status = 400;
            goto end_change_empty;
        }
        else
        {
            // Check TEE has already launched
            enum ValidationStatus validation_status = ValidateStop;

            if (ecall_return_validation_status(*ApiHandler::p_global_eid, &validation_status) != SGX_SUCCESS)
            {
                cprintf_err(felog, "Get validation status failed.\n");
                res.set_content("Get validation status failed", "text/plain");
                res.status = 500;
                goto end_change_empty;
            }
            else if (validation_status == ValidateStop)
            {
                cprintf_err(felog, "TEE has not been fully launched.\n");
                res.set_content("TEE has not been fully launched", "text/plain");
                res.status = 500;
                goto end_change_empty;
            }

            // Start changing empty
            pthread_t wthread;
            if (pthread_create(&wthread, NULL, ApiHandler::change_empty, NULL) != 0)
            {
                res.set_content("Create change empty thread error", "text/plain");
                res.status = 500;
                goto end_change_empty;
            }
            else
            {
                res.set_content("Change empty file success, the empty workload will change in next validation loop", "text/plain");
                res.status = 200;
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
        // Increase empty plot
        cprintf_info(felog, "Start ploting %dG disk (plot thread number: %d) ...\n", change, p_config->plot_thread_num);
        // Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores
        #pragma omp parallel for num_threads(p_config->plot_thread_num)
        for (size_t i = 0; i < (size_t)change; i++)
        {
            ecall_plot_disk(*ApiHandler::p_global_eid, p_config->empty_path.c_str());
        }

        p_config->change_empty_capacity(change);
        cprintf_info(felog, "Increase %dG empty file success, the empty workload will change gradually in next validation loops\n", change);
    }
    else if (change < 0)
    {
        change = -change;
        ecall_decrease_disk(*ApiHandler::p_global_eid, p_config->empty_path.c_str(), (size_t) change);
        cprintf_info(felog, "Decrease %dG empty file success, the empty workload will change in next validation loop\n", change);
    }

    change_empty_mutex.lock();
    in_changing_empty = false;
    change_empty_mutex.unlock();

    return NULL;
}
