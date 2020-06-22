#include "EntryNetwork.h"
#include "HttpClient.h"

namespace http = boost::beast::http;   // from <boost/beast/http.hpp>

extern sgx_enclave_id_t global_eid;
crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: entry network off-chain node sends quote to onchain node to verify identity
 * @param p_config -> configurations
 * @param tee_identity_out -> tee identity result
 * @return: success or failure
 */
bool entry_network(Config *p_config, std::string &tee_identity_out)
{
    sgx_quote_sign_type_t linkable = SGX_UNLINKABLE_SIGNATURE;
    sgx_status_t status, sgxrv;
    sgx_report_t report;
    sgx_report_t qe_report;
    sgx_quote_t *quote;
    sgx_target_info_t target_info;
    sgx_epid_group_id_t epid_gid;
    uint32_t sz = 0;
    uint32_t flags = p_config->flags;
    sgx_quote_nonce_t nonce;
    char *b64quote = NULL;
    char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *)malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char *)spid, p_config->spid.c_str(), p_config->spid.size());
    int i = 0;
    bool entry_status = false;
    int common_tryout = 3;

    // ----- get nonce ----- //
    for (i = 0; i < 2; ++i)
    {
        int retry = 10;
        unsigned char ok = 0;
        uint64_t *np = (uint64_t *)&nonce;
        while (!ok && retry)
            ok = _rdrand64_step(&np[i]);
        if (ok == 0)
        {
            p_log->err("Nonce: RDRAND underflow\n");
            return false;
        }
    }

    if (OPT_ISSET(flags, OPT_LINK))
    {
        linkable = SGX_LINKABLE_SIGNATURE;
    }

    // ----- Get SGX quote ----- //
    memset(&report, 0, sizeof(report));

    status = sgx_init_quote(&target_info, &epid_gid);
    int tryout = 1;
    do
    {
        if (SGX_SUCCESS == status)
            break;

        if (SGX_ERROR_BUSY == status)
        {
            if (tryout > common_tryout)
            {
                p_log->err("Initialize sgx quote tryout!\n");
                return false;
            }
            p_log->info("SGX device is busy, trying again(%d time)...\n", tryout);
            tryout++;
            sleep(1);
        }
        else
        {
            p_log->err("SGX init quote failed!Error code: %08x\n", status);
            return false;
        }
    } while (true);

    status = Ecall_get_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        p_log->err("get_report: %08x\n", status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        p_log->err("sgx_create_report: %08x\n", sgxrv);
        return false;
    }

    // sgx_get_quote_size() has been deprecated, but SGX PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        p_log->err("PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return false;
    }
    if (status != SGX_SUCCESS)
    {
        p_log->err("SGX error while getting quote size: %08x\n", status);
        return false;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        p_log->err("out of memory\n");
        return false;
    }

    memset(quote, 0, sz);
    p_log->debug("========== linkable: %d\n", linkable);
    p_log->debug("========== spid    : %s\n", hexstring(spid, sizeof(sgx_spid_t)));
    p_log->debug("========== nonce   : %s\n", hexstring(&nonce, sizeof(sgx_quote_nonce_t)));
    status = sgx_get_quote(&report, linkable,
            spid, &nonce, NULL, 0, &qe_report, quote, sz);
    if (status != SGX_SUCCESS)
    {
        p_log->err("sgx_get_quote: %08x\n", status);
        return false;
    }

    // ----- Print SGX quote ----- //
    p_log->debug("quote report_data: %s\n", hexstring((const void *)(quote->report_body.report_data.d), sizeof(quote->report_body.report_data.d)));
    p_log->debug("ias quote report version :%d\n", quote->version);
    p_log->debug("ias quote report signtype:%d\n", quote->sign_type);
    p_log->debug("ias quote report epid    :%d\n", *quote->epid_group_id);
    p_log->debug("ias quote report qe svn  :%d\n", quote->qe_svn);
    p_log->debug("ias quote report pce svn :%d\n", quote->pce_svn);
    p_log->debug("ias quote report xeid    :%d\n", quote->xeid);
    p_log->debug("ias quote report basename:%s\n", hexstring(quote->basename.name, 32));
    p_log->debug("ias quote mr enclave     :%s\n", hexstring(&quote->report_body.mr_enclave, 32));

    // Get base64 quote
    b64quote = base64_encode((char *)quote, sz);
    if (b64quote == NULL)
    {
        p_log->err("Could not base64 encode quote\n");
        return false;
    }

    p_log->debug("{\n");
    p_log->debug("\"isvEnclaveQuote\":\"%s\"", b64quote);
    if (OPT_ISSET(flags, OPT_NONCE))
    {
        p_log->debug(",\n\"nonce\":\"");
        print_hexstring(&nonce, 16);
        p_log->debug("\"");
    }

    if (OPT_ISSET(flags, OPT_PSE))
    {
        p_log->debug(",\n\"pseManifest\":\"%s\"", b64manifest);
    }
    p_log->debug("\n}\n");

    // ----- Entry network process ----- //
    HttpClient *client = new HttpClient();
    ApiHeaders headers = {
        {"Ocp-Apim-Subscription-Key", p_config->ias_primary_subscription_key}
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
        ias_res = client->SSLPost(p_config->ias_base_url+p_config->ias_base_path, body, "application/json", headers, HTTP_REQ_INSECURE);
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
        delete client;
        return false;
    }
    p_log->info("Sending quote to IAS service successfully!\n");

    std::vector<const char *> ias_report;
    std::string ias_cer(ias_res["X-IASReport-Signing-Certificate"]);
    std::string ias_sig(ias_res["X-IASReport-Signature"]);
    std::string ias_quote_body(ias_res.body());
    ias_report.push_back(ias_cer.c_str());
    ias_report.push_back(ias_sig.c_str());
    ias_report.push_back(ias_quote_body.c_str());
    ias_report.push_back(p_config->chain_account_id.c_str()); //[3]

    p_log->debug("\n\n----------IAS Report - JSON - Required Fields----------\n\n");
    int version = IAS_API_DEF_VERSION;
    if (version >= 3)
    {
        p_log->debug("version               = %ld\n",
                    ias_res["version"]);
    }
    p_log->debug("id:                   = %s\n",
                std::string(ias_res["id"]).c_str());
    p_log->debug("timestamp             = %s\n",
                std::string(ias_res["timestamp"]).c_str());
    p_log->debug("isvEnclaveQuoteStatus = %s\n",
                std::string(ias_res["isvEnclaveQuoteStatus"]).c_str());
    p_log->debug("isvEnclaveQuoteBody   = %s\n",
                std::string(ias_res["isvEnclaveQuoteBody"]).c_str());
    std::string iasQuoteStr(ias_res["isvEnclaveQuoteBody"]);
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
                std::string(ias_res["platformInfoBlob"]).c_str());
    p_log->debug("revocationReason  = %s\n",
                std::string(ias_res["revocationReason"]).c_str());
    p_log->debug("pseManifestStatus = %s\n",
                std::string(ias_res["pseManifestStatus"]).c_str());
    p_log->debug("pseManifestHash   = %s\n",
                std::string(ias_res["pseManifestHash"]).c_str());
    p_log->debug("nonce             = %s\n",
                std::string(ias_res["nonce"]).c_str());
    p_log->debug("epidPseudonym     = %s\n",
                std::string(ias_res["epidPseudonym"]).c_str());

    // Verify IAS report in enclave
    sgx_ec256_signature_t ensig;
    crust_status_t crust_status;
    sgx_status_t status_ret = Ecall_verify_iasreport(global_eid, &crust_status, const_cast<char**>(ias_report.data()), ias_report.size(), &ensig);
    if (SGX_SUCCESS == status_ret)
    {
        if (CRUST_SUCCESS == crust_status)
        {
            json::JSON identity_json;
            char *p_hex_sig = hexstring_safe((const char *)&ensig, sizeof(sgx_ec256_signature_t));
            identity_json["X-IASReport-Signing-Certificate"] = ias_cer;
            identity_json["X-IASReport-Signature"] = ias_sig;
            identity_json["isvBody"] = ias_quote_body;
            identity_json["account_id"] = p_config->chain_account_id;
            identity_json["sig"] = std::string(p_hex_sig, sizeof(sgx_ec256_signature_t) * 2);
            std::string jsonstr = identity_json.dump();
            // Free temp buffer
            if (p_hex_sig != NULL)
            {
                free(p_hex_sig);
            }
            remove_char(jsonstr, ' ');
            remove_char(jsonstr, '\n');
            remove_char(jsonstr, '\\');
            tee_identity_out = jsonstr;
            entry_status = true;
            p_log->info("Verify IAS report in enclave successfully!\n");
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
        }
    }
    else
    {
        p_log->err("Invoke SGX api failed!\n");
    }


    delete client;

    return entry_status;
}
