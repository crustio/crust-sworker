#include "ApiHandler.h"
#include "json.hpp"

/* Used to show validation status*/
const char *validation_status_strings[] = {"ValidateStop", "ValidateWaiting", "ValidateMeaningful", "ValidateEmpty"};

extern FILE *felog;

/**
 * @description: constructor
 * @param url -> API base url 
 * @param p_global_eid The point for sgx global eid  
 */
ApiHandler::ApiHandler(utility::string_t url, sgx_enclave_id_t *p_global_eid_in)
{
    this->m_listener = new web::http::experimental::listener::http_listener(url);
    this->p_global_eid = p_global_eid_in;
}

/**
 * @description: Start network service
 * @return: Start status
 */
int ApiHandler::start()
{
    try 
    {
        this->m_listener->support(web::http::methods::GET, std::bind(&ApiHandler::handle_get, this, std::placeholders::_1));
        this->m_listener->support(web::http::methods::POST, std::bind(&ApiHandler::handle_post, this, std::placeholders::_1));
        this->m_listener->open().wait();
        return 1;
    }
    catch (const web::http::http_exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
    }
    catch (const std::exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
    }

    return -1;
}

int ApiHandler::stop()
{
    try
    {
        this->m_listener->close().wait();
        return 1;
    }
    catch (const web::http::http_exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
    }
    catch (const std::exception &e)
    {
        cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
    }

    return -1;
}

/**
 * @description: destructor
 */
ApiHandler::~ApiHandler()
{
    delete this->m_listener;
}

/**
 * @description: handle get requests
 * @param message -> http request message
 */
void ApiHandler::handle_get(web::http::http_request message)
{
    /* Handle status request */
    if (message.relative_uri().path() == "/status")
    {
        enum ValidationStatus validation_status = ValidateStop;

        if (ecall_return_validation_status(*this->p_global_eid, &validation_status) != SGX_SUCCESS)
        {
            cfprintf(NULL, CF_ERROR "Get validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        message.reply(web::http::status_codes::OK, (std::string("{'validationStatus':") + validation_status_strings[validation_status] + "}").c_str());
        return;
    }

    /* Handle report request */
    if (message.relative_uri().path() == "/report")
    {
        /* Get block hash from url */
        auto arg_map = web::http::uri::split_query(message.request_uri().query());

        if (arg_map.find("block_hash") == arg_map.end())
        {
            message.reply(web::http::status_codes::BadRequest, "BadRequest");
            return;
        }

        /* Call ecall function to get work report */
        size_t report_len = 0;
        if (ecall_generate_validation_report(*this->p_global_eid, &report_len, arg_map["block_hash"].c_str()) != SGX_SUCCESS)
        {
            cfprintf(NULL, CF_ERROR "Generate validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        char *report = new char[report_len];
        if (ecall_get_validation_report(*this->p_global_eid, report, report_len) != SGX_SUCCESS)
        {
            cfprintf(NULL, CF_ERROR "Get validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        if (report == NULL)
        {
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        message.reply(web::http::status_codes::OK, report);
        delete report;
        return;
    }

    message.reply(web::http::status_codes::BadRequest, "BadRequest");
    return;
}

/**
 * @description: handle post requests
 * @param message -> http request message
 */
void ApiHandler::handle_post(web::http::http_request message)
{
    sgx_status_t status_ret = SGX_SUCCESS;

    /* Deal with entry network */
    if (message.relative_uri().path().compare("/entry/network") == 0)
    {
        int version = IAS_API_DEF_VERSION;
        cfprintf(felog, CF_INFO "Processing entry network application...\n");
        uint32_t qsz;
        size_t dqsz = 0;
        sgx_quote_t *quote;
        std::string b64quote = utility::conversions::to_utf8string(message.extract_string().get());
        if (!get_quote_size(&status_ret, &qsz))
        {
            cfprintf(felog, CF_ERROR "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        if (b64quote.size() == 0)
        {
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        quote = (sgx_quote_t *)malloc(qsz);
        memset(quote, 0, qsz);
        memcpy(quote, base64_decode(b64quote.c_str(), &dqsz), qsz);

        if (ecall_store_quote(*this->p_global_eid, &status_ret, (const char *)quote, qsz) != SGX_SUCCESS)
        {
            cfprintf(felog, CF_ERROR "Store offChain node quote failed!\n");
            message.reply(web::http::status_codes::InternalError, "StoreQuoteError");
            return;
        }
        cfprintf(felog, CF_INFO "Storing quote in enclave successfully!\n");

        /* Request IAS verification */
        web::http::client::http_client_config cfg;
        cfg.set_timeout(std::chrono::seconds(IAS_TIMEOUT));
        Config *p_config = Config::get_instance();
        web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->ias_base_url.c_str(), cfg);
        web::http::http_request ias_request(web::http::methods::POST);
        ias_request.headers().add(U("Ocp-Apim-Subscription-Key"), U(p_config->ias_primary_subscription_key));
        ias_request.headers().add(U("Content-Type"), U("application/json"));
        ias_request.set_request_uri(p_config->ias_base_path.c_str());

        std::string body = "{\n\"isvEnclaveQuote\":\"";
        body.append(b64quote);
        body.append("\"\n}");

        ias_request.set_body(body);

        web::http::http_response response;
        std::string resStr;
        json::JSON res_json;

        // Send quote to IAS service
        int net_tryout = IAS_TRYOUT;
        while (net_tryout >= 0)
        {
            try
            {
                response = self_api_client->request(ias_request).get();
                resStr = response.extract_utf8string().get();
                res_json = json::JSON::Load(resStr);
                break;
            }
            catch (const web::http::http_exception &e)
            {
                cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
                cfprintf(felog, CF_INFO "Trying agin:%d\n", net_tryout);
            }
            catch (const std::exception &e)
            {
                cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
                cfprintf(felog, CF_INFO "Trying agin:%d\n", net_tryout);
            }
            sleep(3);
            net_tryout--;
        }

        if (response.status_code() != IAS_OK)
        {
            cfprintf(felog, CF_ERROR "Request IAS failed!\n");
            message.reply(web::http::status_codes::InternalError, "Request IAS failed!");
            delete self_api_client;
            return;
        }
        cfprintf(felog, CF_INFO "Sending quote to IAS service successfully!\n");


        web::http::http_headers res_headers = response.headers();
        std::vector<const char *> ias_report;
        ias_report.push_back(res_headers["X-IASReport-Signing-Certificate"].c_str());
        ias_report.push_back(res_headers["X-IASReport-Signature"].c_str());
        ias_report.push_back(resStr.c_str());
    
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
                // TODO:Send a verification request to chain
                //cfprintf(felog, CF_INFO "pubkey:%s\n", hexstring((const void *)&ensig.data, sizeof(ensig.data)));
                cfprintf(felog, CF_INFO "Verifying IAS report in enclave successfully!\n");
                message.reply(web::http::status_codes::OK, "Entry network successfully!");
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
                cfprintf(felog, CF_ERROR "Verify IAS report failed!\n");
                message.reply(web::http::status_codes::InternalError, "Verify IAS report failed!");
            }
        }
        else
        {
            cfprintf(felog, CF_ERROR "Invoke SGX api failed!\n");
            message.reply(web::http::status_codes::InternalError, "Invoke SGX api failed!");
        }
        delete self_api_client;
    }

    fflush(felog);

    message.reply(web::http::status_codes::BadRequest, "BadRequest");
    return;
}
