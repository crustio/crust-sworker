#include "ApiHandler.h"
#include "Json.hpp"

using namespace httplib;

/* Used to show validation status*/
const char *validation_status_strings[] = {"ValidateStop", "ValidateWaiting", "ValidateMeaningful", "ValidateEmpty"};

extern FILE *felog;

/**
 * @description: constructor
 * @param url -> API base url 
 * @param p_global_eid The point for sgx global eid  
 */
ApiHandler::ApiHandler(sgx_enclave_id_t *p_global_eid_in)
{
    this->server = new Server();
    this->p_global_eid = p_global_eid_in;
}

int ApiHandler::start()
{
    Config *p_config = Config::get_instance();
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->api_base_url);

    if (!server->is_valid())
    {
        cfprintf(NULL, CF_ERROR "Server encount an error!\n");
        return -1;
    }

    std::string status_path = urlendpoint->base + "/status";
    server->Get(status_path.c_str(), [=](const Request & /*req*/, Response &res) {
        enum ValidationStatus validation_status = ValidateStop;

        if (ecall_return_validation_status(*this->p_global_eid, &validation_status) != SGX_SUCCESS)
        {
            cfprintf(NULL, CF_ERROR "Get validatiom status failed.\n");
            res.set_content("InternalError", "text/plain");
            return;
        }

        res.set_content(std::string("{'validationStatus':") + validation_status_strings[validation_status] + "}", "text/plain");
        return;
    });

    std::string report_path = urlendpoint->base + "/report";
    server->Get(report_path.c_str(), [=](const Request & /*req*/, Response &res) {
        /* Call ecall function to get work report */
        size_t report_len = 0;
        if (ecall_generate_validation_report(*this->p_global_eid, &report_len) != SGX_SUCCESS)
        {
            cfprintf(NULL, CF_ERROR "Generate validation report failed.\n");
            res.set_content("InternalError", "text/plain");
        }

        char *report = new char[report_len];
        if (ecall_get_validation_report(*this->p_global_eid, report, report_len) != SGX_SUCCESS)
        {
            cfprintf(NULL, CF_ERROR "Get validation report failed.\n");
            res.set_content("InternalError", "text/plain");
        }

        if (report == NULL)
        {
            res.set_content("InternalError", "text/plain");
        }

        res.set_content(report, "text/plain");
        delete report;
    });

    std::string entry_path = urlendpoint->base + "/entry/network";
    server->Post(entry_path.c_str(), [&](const Request &req, Response &res) {
        sgx_status_t status_ret = SGX_SUCCESS;
        int version = IAS_API_DEF_VERSION;
        cfprintf(felog, CF_INFO "Processing entry network application...\n");
        uint32_t qsz;
        size_t dqsz = 0;
        sgx_quote_t *quote;
        json::JSON req_json = json::JSON::Load(req.params.find("arg")->second);
        std::string b64quote = req_json["isvEnclaveQuote"].ToString();
        std::string off_chain_crust_address = req_json["crust_address"].ToString();
        std::string off_chain_crust_account_id = req_json["crust_account_id"].ToString();

        if (!get_quote_size(&status_ret, &qsz))
        {
            cfprintf(felog, CF_ERROR "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
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

        if (ecall_store_quote(*this->p_global_eid, &status_ret, (const char *)quote, qsz) != SGX_SUCCESS)
        {
            cfprintf(felog, CF_ERROR "Store offChain node quote failed!\n");
            res.set_content("StoreQuoteError", "text/plain");
            res.status = 401;
            return;
        }
        cfprintf(felog, CF_INFO "Storing quote in enclave successfully!\n");

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
                cfprintf(NULL, CF_ERROR "Send to ias failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
                sleep(3);
                net_tryout--;
                continue;
            }
            break;
        }

        if (!(ias_res && ias_res->status == 200))
        {
            cfprintf(felog, CF_ERROR "Request IAS failed!\n");
            res.set_content("Request IAS failed!", "text/plain");
            res.status = 402;
            delete client;
            return;
        }
        res_json = json::JSON::Load(ias_res->body);
        cfprintf(felog, CF_INFO "Sending quote to IAS service successfully!\n");

        Headers res_headers = ias_res->headers;
        std::vector<const char *> ias_report;
        ias_report.push_back(res_headers.find("X-IASReport-Signing-Certificate")->second.c_str());
        ias_report.push_back(res_headers.find("X-IASReport-Signature")->second.c_str());
        ias_report.push_back(ias_res->body.c_str());

        // Identity info
        ias_report.push_back(off_chain_crust_account_id.c_str()); //[3]
        // TODO: hard code “Alice” identity as validator for now, waiting for crust chain finishs genesis validators
        // ias_report.push_back(p_config->crust_account_id.c_str()); //[4]
        ias_report.push_back("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"); //[4]

        // Print IAS report
        if (p_config->verbose)
        {
            // TODO: seal log code into functions
            cfprintf(felog, "\n\n----------IAS Report - JSON - Required Fields----------\n\n");
            if (version >= 3)
            {
                fprintf(felog, "version               = %ld\n",
                        res_json["version"].ToInt());
            }
            cfprintf(felog, "id:                   = %s\n",
                     res_json["id"].ToString().c_str());
            cfprintf(felog, "timestamp             = %s\n",
                     res_json["timestamp"].ToString().c_str());
            cfprintf(felog, "isvEnclaveQuoteStatus = %s\n",
                     res_json["isvEnclaveQuoteStatus"].ToString().c_str());
            cfprintf(felog, "isvEnclaveQuoteBody   = %s\n",
                     res_json["isvEnclaveQuoteBody"].ToString().c_str());
            std::string iasQuoteStr = res_json["isvEnclaveQuoteBody"].ToString();
            size_t qs;
            char *ppp = base64_decode(iasQuoteStr.c_str(), &qs);
            sgx_quote_t *ias_quote = (sgx_quote_t *)malloc(qs);
            memset(ias_quote, 0, qs);
            memcpy(ias_quote, ppp, qs);
            cfprintf(felog, "========== ias quote report data:%s\n", hexstring(ias_quote->report_body.report_data.d, sizeof(ias_quote->report_body.report_data.d)));
            cfprintf(felog, "ias quote report version:%d\n", ias_quote->version);
            cfprintf(felog, "ias quote report signtype:%d\n", ias_quote->sign_type);
            cfprintf(felog, "ias quote report basename:%s\n", hexstring(&ias_quote->basename, sizeof(sgx_basename_t)));
            cfprintf(felog, "ias quote report mr_enclave:%s\n", hexstring(&ias_quote->report_body.mr_enclave, sizeof(sgx_measurement_t)));

            cfprintf(felog, "\n\n----------IAS Report - JSON - Optional Fields----------\n\n");

            cfprintf(felog, "platformInfoBlob  = %s\n",
                     res_json["platformInfoBlob"].ToString().c_str());
            cfprintf(felog, "revocationReason  = %s\n",
                     res_json["revocationReason"].ToString().c_str());
            cfprintf(felog, "pseManifestStatus = %s\n",
                     res_json["pseManifestStatus"].ToString().c_str());
            cfprintf(felog, "pseManifestHash   = %s\n",
                     res_json["pseManifestHash"].ToString().c_str());
            cfprintf(felog, "nonce             = %s\n",
                     res_json["nonce"].ToString().c_str());
            cfprintf(felog, "epidPseudonym     = %s\n",
                     res_json["epidPseudonym"].ToString().c_str());
        }

        /* Verify IAS report in enclave */
        ias_status_t ias_status_ret;
        entry_network_signature ensig;
        status_ret = ecall_verify_iasreport(*this->p_global_eid, &ias_status_ret, (const char **)ias_report.data(), ias_report.size(), &ensig);
        if (SGX_SUCCESS == status_ret)
        {
            if (ias_status_ret == IAS_VERIFY_SUCCESS)
            {
                json::JSON identity_json;
                identity_json["pub_key"] = hexstring((const char *)&ensig.pub_key, sizeof(ensig.pub_key));
                // TODO: substrust will convert address to account id automaticly
                identity_json["account_id"] = off_chain_crust_address;
                identity_json["validator_pub_key"] = hexstring((const char *)&ensig.validator_pub_key, sizeof(ensig.validator_pub_key));
                // TODO: hard code “Alice” identity as validator for now, waiting for crust chain finishs genesis validators
                // identity_json["validator_account_id"] = p_config->crust_address;
                identity_json["validator_account_id"] = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
                identity_json["sig"] = hexstring((const char *)&ensig.signature, sizeof(ensig.signature));
                std::string jsonstr = identity_json.dump();
                // Delete space
                jsonstr.erase(std::remove(jsonstr.begin(), jsonstr.end(), ' '), jsonstr.end());
                // Delete line break
                jsonstr.erase(std::remove(jsonstr.begin(), jsonstr.end(), '\n'), jsonstr.end());

                res.set_content(jsonstr.c_str(), "text/plain");
                cfprintf(felog, CF_INFO "Verifying IAS report in enclave successfully!\n");
            }
            else
            {
                switch (ias_status_ret)
                {
                case IAS_BADREQUEST:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Bad request!!\n");
                    break;
                case IAS_UNAUTHORIZED:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Unauthorized!!\n");
                    break;
                case IAS_NOT_FOUND:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Not found!!\n");
                    break;
                case IAS_SERVER_ERR:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Server error!!\n");
                    break;
                case IAS_UNAVAILABLE:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Unavailable!!\n");
                    break;
                case IAS_INTERNAL_ERROR:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Internal error!!\n");
                    break;
                case IAS_BAD_CERTIFICATE:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Bad certificate!!\n");
                    break;
                case IAS_BAD_SIGNATURE:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Bad signature!!\n");
                    break;
                case IAS_REPORTDATA_NE:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Report data not equal!!\n");
                    break;
                case IAS_GET_REPORT_FAILED:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Get report in current enclave failed!!\n");
                    break;
                case IAS_BADMEASUREMENT:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Bad enclave code measurement!!\n");
                    break;
                case IAS_GETPUBKEY_FAILED:
                    cfprintf(felog, CF_ERROR "Verify IAS report failed! Get public key from certificate failed!!\n");
                    break;
                case CRUST_SIGN_PUBKEY_FAILED:
                    cfprintf(felog, CF_ERROR "Sign public key failed!!\n");
                    break;
                default:
                    cfprintf(felog, CF_ERROR "Unknow return status!\n");
                }
                res.set_content("Verify IAS report failed!", "text/plain");
                res.status = 403;
            }
        }
        else
        {
            cfprintf(felog, CF_ERROR "Invoke SGX api failed!\n");
            res.set_content("Invoke SGX api failed!", "text/plain");
            res.status = 404;
        }
        delete client;
    });

    server->listen(urlendpoint->ip.c_str(), urlendpoint->port);

    return 1;
}

int ApiHandler::stop()
{
    this->server->stop();
    return -1;
}

/**
 * @description: destructor
 */
ApiHandler::~ApiHandler()
{
    delete this->server;
}
