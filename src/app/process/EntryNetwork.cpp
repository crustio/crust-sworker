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
    bool entry_status = true;
    int common_tryout = 3;

    /* get nonce */
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

    /* Get SGX quote */
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

    status = ecall_get_report(global_eid, &sgxrv, &report, &target_info);
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

    /* Print SGX quote */
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

    /* Send quote to validation node */
    p_log->info("Sending quote to on-chain node...\n");

    /* Send quote to validation node, try out 3 times for network error. */
    // Get signed identity info
    std::string req_data;
    std::string send_data;
    crust_status_t crust_status = CRUST_SUCCESS;
    send_data.append(b64quote);
    send_data.append(p_config->chain_address);
    sgx_ec256_signature_t send_data_sig;
    sgx_status_t sgx_status = ecall_sign_network_entry(global_eid, &crust_status, 
            send_data.c_str(), send_data.size(), &send_data_sig);
    if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
    {
        p_log->err("Sign entry network data failed!\n");
        return false;
    }
    char *p_hex_sig = hexstring_safe(&send_data_sig, sizeof(sgx_ec256_signature_t));
    std::string signature_str(p_hex_sig, sizeof(sgx_ec256_signature_t) * 2);
    if (p_hex_sig != NULL)
    {
        free(p_hex_sig);
    }

    req_data.append("{ \"isvEnclaveQuote\": \"");
    req_data.append(b64quote).append("\", \"chain_address\": \"");
    req_data.append(p_config->chain_address).append("\", \"chain_account_id\": \"");
    req_data.append(p_config->chain_account_id.c_str()).append("\", \"signature\": \"");
    req_data.append(signature_str).append("\" }");
    int net_tryout = IAS_TRYOUT;

    // Send to validation node
    HttpClient *client = new HttpClient();
    std::string url = p_config->validator_api_base_url + "/entry/network";
    http::response<http::string_body> res;
    while (net_tryout > 0)
    {
        res = client->Post(url, req_data);
        if ((int)res.result() != 200)
        {
            p_log->info("Sending quote to verify failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
            sleep(3);
            net_tryout--;
            continue;
        }
        break;
    }
    if ((int)res.result() != 200)
    {
        p_log->err("Entry network failed!Error :%d\n", res.result());
        entry_status = false;
        goto cleanup;
    }

    tee_identity_out = res.body();

cleanup:

    delete client;

    return entry_status;
}
