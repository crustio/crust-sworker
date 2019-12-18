#include "ApiHandler.h"

ApiHandler *api_handler = NULL;
/* Used to show validation status*/
const char *validation_status_strings[] = {"ValidateStop", "ValidateWaiting", "ValidateMeaningful", "ValidateEmpty"};

/**
 * @description: new a global API handler
 * @param url -> API base url 
 * @param p_global_eid -> The point for sgx global eid 
 * @return: the point of API handler
 */
ApiHandler *new_api_handler(const char *url, sgx_enclave_id_t *p_global_eid)
{
    if (api_handler != NULL)
    {
        delete api_handler;
    }

    api_handler = new ApiHandler(url, p_global_eid);
    return api_handler;
}

/**
 * @description: get the global API handler
 * @return: the point of API handler
 */
ApiHandler *get_api_handler(void)
{
    if (api_handler == NULL)
    {
        printf("Please use new_api_handler(url, &global_eid) frist.\n");
        exit(-1);
    }

    return api_handler;
}

/**
 * @description: constructor
 * @param url -> API base url 
 * @param p_global_eid The point for sgx global eid  
 */
ApiHandler::ApiHandler(utility::string_t url, sgx_enclave_id_t *p_global_eid_in) : m_listener(url)
{
    this->p_global_eid = p_global_eid_in;
    this->m_listener.support(web::http::methods::GET, std::bind(&ApiHandler::handle_get, this, std::placeholders::_1));
    this->m_listener.support(web::http::methods::POST, std::bind(&ApiHandler::handle_post, this, std::placeholders::_1));
    this->m_listener.open().wait();
}

/**
 * @description: destructor
 */
ApiHandler::~ApiHandler()
{
    this->m_listener.close().wait();
    delete this->p_global_eid;
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
            printf("Get validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        message.reply(web::http::status_codes::OK, std::string("{'validationStatus':") + validation_status_strings[validation_status] + "}");
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
            printf("Generate validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        char *report = new char[report_len];
        if (ecall_get_validation_report(*this->p_global_eid, report, report_len) != SGX_SUCCESS)
        {
            printf("Get validation failed.\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        if (report == NULL)
        {
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        message.reply(web::http::status_codes::OK, report);
        return;
    }

    message.reply(web::http::status_codes::BadRequest, "BadRequest");
    return;
};

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
        uint32_t qsz;
        std::string b64quote = utility::conversions::to_utf8string(message.extract_string().get());
	    if (! get_quote_size(&status_ret, &qsz)) {
	    	printf("[ERROR] PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
	    	return;
	    }
        
        if (b64quote.size() == 0) 
        {
            message.reply(web::http::status_codes::InternalError, "InternalError");
            return;
        }

        size_t dqsz = 0;
        sgx_quote_t *quote = (sgx_quote_t*)malloc(qsz);
        memset(quote, 0, qsz);
        memcpy(quote, base64_decode(b64quote.c_str(), &dqsz), qsz);

        printf("[INFO] Store quote in enclave\n");
        if (ecall_store_quote(*this->p_global_eid, &status_ret, (const char*)quote, qsz) != SGX_SUCCESS) 
        {
            printf("Store offChain node quote failed!\n");
            message.reply(web::http::status_codes::InternalError, "StoreQuoteError");
            return;
        }

        /* Request IAS verification */
        web::http::client::http_client_config cfg;
        cfg.set_timeout(std::chrono::seconds(IAS_TIMEOUT));
        web::http::client::http_client *self_api_client = new web::http::client::http_client(get_config()->ias_base_url.c_str(), cfg);
        web::http::http_request ias_request(web::http::methods::POST);
        ias_request.headers().add(U("Ocp-Apim-Subscription-Key"), U(get_config()->ias_primary_subscription_key));
        ias_request.headers().add(U("Content-Type"), U("application/json"));
        ias_request.set_request_uri(get_config()->ias_base_path.c_str());

        std::string body = "{\n\"isvEnclaveQuote\":\"";
        body.append(b64quote);
        body.append("\"\n}");

        ias_request.set_body(body);

        web::http::http_response response;
        std::string resStr;
        web::json::value res_json;

        // Send quote to IAS service
        printf("[INFO] Sending quote to IAS service...");
        int net_tryout = IAS_TRYOUT;
        while(net_tryout >= 0) 
        {
            try {
                response = self_api_client->request(ias_request).get();
                resStr = response.extract_utf8string().get();
                res_json = response.extract_json().get();
                break;
            } catch(const web::http::http_exception& e) {
                printf("[ERROR] HTTP Exception: %s\n", e.what());
                printf("[INFO] Trying agin:%d\n", net_tryout);
            } catch(const std::exception& e) {
                printf("[ERROR] HTTP throw: %s\n", e.what());
                printf("[INFO] Trying agin:%d\n", net_tryout);
            }
            usleep(3000);
            net_tryout--;
        }

        if (response.status_code() != IAS_OK)
        {
            printf("failed\n");
            printf("[ERROR] Request IAS failed!\n");
            message.reply(web::http::status_codes::InternalError, "InternalError");
            delete self_api_client;
            return;
        }

        web::http::http_headers res_headers = response.headers();
        std::vector<const char *> ias_report;
        ias_report.push_back(res_headers["X-IASReport-Signing-Certificate"].c_str());
        ias_report.push_back(res_headers["X-IASReport-Signature"].c_str());
        ias_report.push_back(resStr.c_str());

        // TODO:log file
		if ( get_config()->verbose ) {
			printf("\nIAS Report - JSON - Required Fields\n");
			if ( version >= 3 ) {
				printf("version               = %d\n",
					res_json["version"].as_integer());
			}
			printf("id:                   = %s\n",
				res_json["id"].as_string().c_str());
			printf("timestamp             = %s\n",
				res_json["timestamp"].as_string().c_str());
			printf("isvEnclaveQuoteStatus = %s\n",
				res_json["isvEnclaveQuoteStatus"].as_string().c_str());
			printf("isvEnclaveQuoteBody   = %s\n",
				res_json["isvEnclaveQuoteBody"].as_string().c_str());
            std::string iasQuoteStr = res_json["isvEnclaveQuoteBody"].as_string();
            size_t qs;
            char *ppp = base64_decode(iasQuoteStr.c_str(), &qs);
            sgx_quote_t *ias_quote = (sgx_quote_t *) malloc(qs);
            memset(ias_quote, 0, qs);
            memcpy(ias_quote, ppp, qs);
            printf("========== ias quote report data:%s\n",hexstring(ias_quote->report_body.report_data.d,
                    sizeof(ias_quote->report_body.report_data.d)));
            printf("ias quote report version:%d\n",ias_quote->version);
            printf("ias quote report signtype:%d\n",ias_quote->sign_type);
            printf("ias quote report basename:%d\n",ias_quote->basename);

			printf("\nIAS Report - JSON - Optional Fields\n");

			printf("platformInfoBlob  = %s\n",
				res_json["platformInfoBlob"].as_string().c_str());
			printf("revocationReason  = %s\n",
				res_json["revocationReason"].as_string().c_str());
			printf("pseManifestStatus = %s\n",
				res_json["pseManifestStatus"].as_string().c_str());
			printf("pseManifestHash   = %s\n",
				res_json["pseManifestHash"].as_string().c_str());
			printf("nonce             = %s\n",
				res_json["nonce"].as_string().c_str());
			printf("epidPseudonym     = %s\n",
				res_json["epidPseudonym"].as_string().c_str());
		}
        printf("success\n");

        /* Verify IAS report in enclave */
        printf("[INFO] Verifying IAS report in enclave...");
        ias_status_t ias_status_ret;
        if(ecall_verify_iasreport(*this->p_global_eid, &ias_status_ret, ias_report.data(), ias_report.size()) == SGX_SUCCESS)
        {
            if(ias_status_ret == IAS_VERIFY_SUCCESS) 
            {
                // TODO:Send a verification request to chain
                printf("success\n");
                message.reply(web::http::status_codes::OK, "Entry network successfully!");
            } 
            else 
            {
                printf("failed\n");
                switch(ias_status_ret) {
                    case IAS_BADREQUEST:
                        printf("Verify IAS report failed! Bad request!!\n");
                        break;
                    case IAS_UNAUTHORIZED:
                        printf("Verify IAS report failed! Unauthorized!!\n");
                        break;
                    case IAS_NOT_FOUND:
                        printf("Verify IAS report failed! Not found!!\n");
                        break;
                    case IAS_SERVER_ERR:
                        printf("Verify IAS report failed! Server error!!\n");
                        break;
                    case IAS_UNAVAILABLE:
                        printf("Verify IAS report failed! Unavailable!!\n");
                        break;
                    case IAS_INTERNAL_ERROR:
                        printf("Verify IAS report failed! Internal error!!\n");
                        break;
                    case IAS_BAD_CERTIFICATE:
                        printf("Verify IAS report failed! Bad certificate!!\n");
                        break;
                    case IAS_BAD_SIGNATURE:
                        printf("Verify IAS report failed! Bad signature!!\n");
                        break;
                    case IAS_REPORTDATA_NE:
                        printf("Verify IAS report failed! Report data not equal!!\n");
                        break;
                    case IAS_GET_REPORT_FAILED:
                        printf("Verify IAS report failed! Get report in current enclave failed!!\n");
                        break;
                    case IAS_BADMEASUREMENT:
                        printf("Verify IAS report failed! Bad enclave code measurement!!\n");
                        break;
                    case IAS_GETPUBKEY_FAILED:
                        printf("Verify IAS report failed! Get public key from certificate failed!!\n");
                        break;
                    default:
                        printf("Unknow return status!\n");
                }
                message.reply(web::http::status_codes::InternalError, "Verify IAS report failed!");
            }
        } 
        else 
        {
            printf("failed\n");
	        printf("Error: Invoke SGX api failed!\n");
            message.reply(web::http::status_codes::InternalError, "Invoke SGX api failed!");
        }   
        delete self_api_client;
    }
}
