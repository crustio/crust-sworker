#include "EntryNetwork.h"
#include "ECalls.h"

namespace http = boost::beast::http;   // from <boost/beast/http.hpp>

extern sgx_enclave_id_t global_eid;
crust::Log *p_log = crust::Log::get_instance();

#ifdef SGX_TYPE_EPID
/**
 * @description: Entry network off-chain node sends quote to onchain node to verify identity, EPID mode
 * @return: Result status
 */
crust_status_t entry_network()
{
    p_log->info("Entrying network...\n");
    sgx_quote_sign_type_t linkable = SGX_UNLINKABLE_SIGNATURE;
    sgx_status_t status, sgxrv;
    sgx_report_t report;
    sgx_report_t qe_report;
    sgx_quote_t *quote;
    sgx_target_info_t target_info;
    sgx_epid_group_id_t epid_gid;
    uint32_t sz = 0;
    uint32_t flags = IAS_FLAGS;
    sgx_quote_nonce_t nonce;
    char *b64quote = NULL;
    char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *)malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char *)spid, IAS_SPID, strlen(IAS_SPID));
    int i = 0;
    int common_tryout = 5;
    crust_status_t crust_status = CRUST_SUCCESS;

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
            return CRUST_UNEXPECTED_ERROR;
        }
    }

    if (OPT_ISSET(flags, OPT_LINK))
    {
        linkable = SGX_LINKABLE_SIGNATURE;
    }

    // ----- Get SGX quote ----- //
    memset(&report, 0, sizeof(report));

    int tryout = 1;
    do
    {
        status = sgx_init_quote(&target_info, &epid_gid);

        if (SGX_SUCCESS == status)
            break;

        switch (status)
        {
            case SGX_ERROR_BUSY:
                p_log->info("SGX device is busy, trying again(%d time)...\n", tryout);
                break;
            case SGX_ERROR_SERVICE_TIMEOUT:
                p_log->info("The request to AE service timed out, trying again(%d time)...\n", tryout);
                break;
            case SGX_ERROR_NETWORK_FAILURE:
                p_log->info("AES network connecting or proxy setting issue is encountered, trying again(%d time)...\n", tryout);
                break;
            case SGX_ERROR_UPDATE_NEEDED:
                p_log->err("SGX init quote failed!You should upgrade your BIOS.Error code:%lx\n", status);
                return CRUST_DEVICE_ERROR;
            default:
                p_log->err("SGX init quote failed!Error code: %lx\n", status);
                return CRUST_INIT_QUOTE_FAILED;
        }

        if (tryout > common_tryout)
        {
            p_log->err("Initialize sgx quote tryout!\n");
            return CRUST_INIT_QUOTE_FAILED;
        }

        tryout++;
        sleep(60);

    } while (true);

    status = Ecall_get_quote_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        p_log->err("get_report: %lx\n", status);
        return CRUST_UNEXPECTED_ERROR;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        p_log->err("sgx_create_report: %lx\n", sgxrv);
        return CRUST_UNEXPECTED_ERROR;
    }

    // sgx_get_quote_size() has been deprecated, but SGX PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        p_log->err("PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return CRUST_UNEXPECTED_ERROR;
    }
    if (status != SGX_SUCCESS)
    {
        p_log->err("SGX error while getting quote size: %lx\n", status);
        return CRUST_UNEXPECTED_ERROR;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        p_log->err("out of memory\n");
        return CRUST_MALLOC_FAILED;
    }

    memset(quote, 0, sz);
    p_log->debug("========== linkable: %d\n", linkable);
    p_log->debug("========== spid    : %s\n", hexstring(spid, sizeof(sgx_spid_t)));
    p_log->debug("========== nonce   : %s\n", hexstring(&nonce, sizeof(sgx_quote_nonce_t)));
    status = sgx_get_quote(&report, linkable,
            spid, &nonce, NULL, 0, &qe_report, quote, sz);
    if (status != SGX_SUCCESS)
    {
        p_log->err("sgx_get_quote: %lx\n", status);
        return CRUST_UNEXPECTED_ERROR;
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
        return CRUST_UNEXPECTED_ERROR;
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
        {"Ocp-Apim-Subscription-Key", IAS_PRIMARY_SUBSCRIPTION_KEY}
    };
    std::string body = "{\n\"isvEnclaveQuote\":\"";
    body.append(b64quote);
    body.append("\"\n}");
    std::string resStr;
    http::response<http::string_body> ias_res;
    // Send quote to IAS service
    int net_tryout = IAS_TRYOUT;
    std::string ias_report_url(IAS_BASE_URL);
    ias_report_url.append(IAS_REPORT_PATH);
    while (net_tryout > 0)
    {
        ias_res = client->SSLPost(ias_report_url, body, "application/json", headers, HTTP_REQ_INSECURE);
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
        return CRUST_UNEXPECTED_ERROR;
    }
    p_log->info("Sending quote to IAS service successfully!\n");

    std::vector<const char *> ias_report;
    std::string ias_cer(ias_res["X-IASReport-Signing-Certificate"]);
    std::string ias_sig(ias_res["X-IASReport-Signature"]);
    std::string ias_quote_body(ias_res.body());
    ias_report.push_back(ias_cer.c_str());
    ias_report.push_back(ias_sig.c_str());
    ias_report.push_back(ias_quote_body.c_str());

    p_log->debug("\n\n----------IAS Report - JSON - Required Fields----------\n\n");
    json::JSON ias_body_json = json::JSON::Load_unsafe(ias_res.body());
    int version = IAS_API_DEF_VERSION;
    if (version >= 3)
    {
        p_log->debug("version                     = %ld\n",
                    ias_body_json["version"].ToInt());
    }
    p_log->debug("id:                         = %s\n",
                ias_body_json["id"].ToString().c_str());
    p_log->debug("timestamp                   = %s\n",
                ias_body_json["timestamp"].ToString().c_str());
    p_log->debug("isvEnclaveQuoteStatus       = %s\n",
                ias_body_json["isvEnclaveQuoteStatus"].ToString().c_str());
    p_log->debug("isvEnclaveQuoteBody         = %s\n",
                ias_body_json["isvEnclaveQuoteBody"].ToString().c_str());
    std::string iasQuoteStr(ias_body_json["isvEnclaveQuoteBody"].ToString());
    size_t qs;
    char *ppp = base64_decode(iasQuoteStr.c_str(), &qs);
    sgx_quote_t *ias_quote = (sgx_quote_t *)malloc(qs);
    memset(ias_quote, 0, qs);
    memcpy(ias_quote, ppp, qs);
    p_log->debug("ias quote report data       = %s\n", hexstring(ias_quote->report_body.report_data.d, sizeof(ias_quote->report_body.report_data.d)));
    p_log->debug("ias quote report version    = %d\n", ias_quote->version);
    p_log->debug("ias quote report signtype   = %d\n", ias_quote->sign_type);
    p_log->debug("ias quote report basename   = %s\n", hexstring(&ias_quote->basename, sizeof(sgx_basename_t)));
    p_log->debug("ias quote report mr_enclave = %s\n", hexstring(&ias_quote->report_body.mr_enclave, sizeof(sgx_measurement_t)));

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
    p_log->debug("epidPseudonym     = %s\n\n",
                std::string(ias_res["epidPseudonym"]).c_str());

    // Verify and upload IAS report
    sgx_status_t status_ret = Ecall_gen_upload_epid_identity(global_eid, &crust_status, const_cast<char**>(ias_report.data()), ias_report.size());
    if (SGX_SUCCESS == status_ret)
    {
        switch (crust_status)
        {
        case CRUST_SUCCESS:
            p_log->info("Entry network application has been sent successfully!\n");
            break;
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
        case CRUST_SWORKER_UPGRADE_NEEDED:
            p_log->err("Sworker upgrade needed!!\n");
            break;
        default:
            p_log->err("Unknown return status!\n");
        }
    }
    else
    {
        p_log->err("Invoke SGX api failed!\n");
        crust_status = CRUST_UNEXPECTED_ERROR;
    }


    delete client;

    return crust_status;
}

#else
/**
 * @description: Entry network with ECDSA off-chain node sends quote to onchain node to verify identity, ECDSA mode
 * @return: Result status
 */
crust_status_t entry_network()
{
    p_log->info("Entrying network...\n");
    sgx_status_t sgxrv;
    quote3_error_t status = SGX_QL_SUCCESS;
    sgx_report_t report;
    sgx_target_info_t target_info;
    uint32_t quote_sz = 0;
    sgx_quote_nonce_t nonce;
    int common_tryout = 5;

    // ----- get nonce ----- //
    for (int i = 0; i < 2; ++i)
    {
        int retry = 10;
        unsigned char ok = 0;
        uint64_t *np = (uint64_t *)&nonce;
        while (!ok && retry)
            ok = _rdrand64_step(&np[i]);
        if (ok == 0)
        {
            p_log->err("Nonce: RDRAND underflow\n");
            return CRUST_UNEXPECTED_ERROR;
        }
    }

    // ----- Get SGX quote ----- //
    memset(&report, 0, sizeof(report));

    int tryout = 1;
    do
    {
        status = sgx_qe_get_target_info(&target_info);

        if (SGX_QL_SUCCESS == status)
            break;

        switch (status)
        {
        case SGX_QL_ERROR_INVALID_PARAMETER:
            p_log->err("p_target_info must not be NULL.\n");
            break;
        case SGX_QL_ERROR_UNEXPECTED:
            p_log->err("Unexpected internal error occurred.\n");
            break;
        case SGX_QL_ENCLAVE_LOAD_ERROR:
            p_log->err("Unable to load the enclaves required to initialize the attestation key. error or some other loading infrastructure errors.\n");
            break;
        case SGX_QL_ENCLAVE_LOST:
            p_log->err("Enclave is lost after power transition or used in a child process created by linux:fork().\n");
            break;
        case SGX_QL_NO_PLATFORM_CERT_DATA:
            p_log->err("The platform quote provider library doesn't have the platform certification data for this platform.\n");
            break;
        case SGX_QL_NO_DEVICE:
            p_log->err("Can't open SGX device. This error happens only when running in out-of-process mode.\n");
            break;
        case SGX_QL_SERVICE_UNAVAILABLE:
            p_log->err("Indicates AESM didn't respond or the requested service is not supported. This error happens only when running in out-of-process mode.\n");
            break;
        case SGX_QL_NETWORK_FAILURE:
            p_log->err("Network connection or proxy setting issue is encountered. This error happens only when running in out-of-process mode.\n");
            break;
        case SGX_QL_SERVICE_TIMEOUT:
            p_log->err("The request to out-of-process service has timed out. This error happens only when running in out- of-process mode.\n");
            break;
        case SGX_QL_ERROR_BUSY:
            p_log->err("The requested service is temporarily not available. This error happens only when running in out- of-process mode.\n");
            break;
        case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
            p_log->err("Unsupported attestation key ID.\n");
            break;
        case SGX_QL_UNKNOWN_MESSAGE_RESPONSE:
            p_log->err("Unexpected error from the attestation infrastructure while retrieving the platform data.\n");
            break;
        case SGX_QL_ERROR_MESSAGE_PARSING_ERROR:
            p_log->err("Generic message parsing error from the attestation infrastructure while retrieving the platform data.\n");
            break;
        case SGX_QL_PLATFORM_UNKNOWN:
            p_log->err("This platform is an unrecognized SGX platform.\n");
            break;
        default:
            p_log->err("SGX init quote failed!Error code: %lx\n", status);
            return CRUST_INIT_QUOTE_FAILED;
        }

        if (tryout > common_tryout)
        {
            p_log->err("Initialize sgx quote tryout!\n");
            return CRUST_INIT_QUOTE_FAILED;
        }

        tryout++;
        sleep(60);

    } while (true);

    sgx_status_t sgx_ret = Ecall_get_quote_report(global_eid, &sgxrv, &report, &target_info);
    if (sgx_ret != SGX_SUCCESS)
    {
        p_log->err("get_report: %lx\n", sgx_ret);
        return CRUST_UNEXPECTED_ERROR;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        p_log->err("sgx_create_report: %lx\n", sgxrv);
        return CRUST_UNEXPECTED_ERROR;
    }

    // sgx_get_quote_size() has been deprecated, but SGX PSW may be too old
    // so use a wrapper function.
    //if (!get_quote_size(&status, &quote_sz))
    if (SGX_QL_SUCCESS != sgx_qe_get_quote_size(&quote_sz))
    {
        p_log->err("PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return CRUST_UNEXPECTED_ERROR;
    }
    if (status != SGX_QL_SUCCESS)
    {
        p_log->err("SGX error while getting quote size: %lx\n", status);
        return CRUST_UNEXPECTED_ERROR;
    }

    uint8_t *p_quote_buffer = (uint8_t *)malloc(quote_sz);
    if (p_quote_buffer == NULL)
    {
        p_log->err("out of memory\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(p_quote_buffer, 0, quote_sz);

    status = sgx_qe_get_quote(&report, quote_sz, p_quote_buffer);
    if (status != SGX_QL_SUCCESS)
    {
        p_log->err("sgx_get_quote: %lx\n", status);
        return CRUST_UNEXPECTED_ERROR;
    }
    _sgx_quote3_t *quote = (_sgx_quote3_t*)p_quote_buffer;
    uint8_t *p_pub_key = reinterpret_cast<uint8_t *>(&quote->report_body.report_data);
    uint8_t *p_mr_enclave = reinterpret_cast<uint8_t *>(&quote->report_body.mr_enclave);

    // ----- Print SGX quote ----- //
    p_log->debug("quote info:\n");
    p_log->debug("enclave public key:%s\n", hexstring_safe(p_pub_key, sizeof(sgx_ec256_public_t)).c_str());
    p_log->debug("quote mrenclave   :%s\n", hexstring_safe(p_mr_enclave, sizeof(sgx_measurement_t)).c_str());

    // ----- Entry network process ----- //
    crust_status_t crust_status = CRUST_SUCCESS;
    if (SGX_SUCCESS != (sgx_ret = Ecall_gen_upload_ecdsa_quote(global_eid, &crust_status, p_quote_buffer, quote_sz)))
    {
        p_log->err("Generate and upload quote to registry chain failed due to invoke SGX API failed, error code:%lx\n", sgx_ret);
        return CRUST_SGX_FAILED;
    }
    if (CRUST_SUCCESS != crust_status)
    {
        p_log->err("Generate and upload identity to registry chain failed, error code:%lx\n", crust_status);
        return crust_status;
    }
    // Send quote to IAS service
    p_log->info("Verify quote successfully!\n");

    // Get verification result from registry chain
    std::string res = crust::Chain::get_instance()->get_ecdsa_verify_result();
    if (res.size() == 0)
    {
        p_log->err("Get ecdsa verify result failed!");
        return CRUST_UNEXPECTED_ERROR;
    }
    p_log->info("Get result from registry chain successfully!\n");

    // Upload final identity to crust chain
    if (SGX_SUCCESS != (sgx_ret = Ecall_gen_upload_ecdsa_identity(global_eid, &crust_status, res.c_str(), res.size())))
    {
        p_log->err("Generate and upload identity to crust chain failed due to invoke SGX API failed, error code:%lx\n", sgx_ret);
        return CRUST_SGX_FAILED;
    }
    if (CRUST_SUCCESS != crust_status)
    {
        p_log->err("Generate and upload identity to crust chain failed, error code:%lx\n", crust_status);
        return crust_status;
    }
    p_log->info("Enter network successfully!\n");

    return CRUST_SUCCESS;
}
#endif
