#include "Identity.h"
#include "Workload.h"
#include "Persistence.h"
#include "EJson.h"
#include "Report.h"

using namespace std;

// Protect metadata 
sgx_thread_mutex_t g_metadata_mutex = SGX_THREAD_MUTEX_INITIALIZER;
// Upgrade generate metadata 
sgx_thread_mutex_t g_gen_work_report = SGX_THREAD_MUTEX_INITIALIZER;
// Upgrade buffer
uint8_t *g_upgrade_buffer = NULL;
size_t g_upgrade_buffer_offset = 0;

// Intel SGX root certificate
static const char INTELSGXATTROOTCA[] = "-----BEGIN CERTIFICATE-----" "\n"
"MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV" "\n"
"BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV" "\n"
"BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0" "\n"
"YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy" "\n"
"MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL" "\n"
"U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD" "\n"
"DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G" "\n"
"CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e" "\n"
"LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh" "\n"
"rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT" "\n"
"L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe" "\n"
"NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ" "\n"
"byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H" "\n"
"afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf" "\n"
"6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM" "\n"
"RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX" "\n"
"MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50" "\n"
"L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW" "\n"
"BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr" "\n"
"NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq" "\n"
"hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir" "\n"
"IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ" "\n"
"sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi" "\n"
"zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra" "\n"
"Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA" "\n"
"152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB" "\n"
"3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O" "\n"
"DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv" "\n"
"DaVzWh5aiEx+idkSGMnX" "\n"
"-----END CERTIFICATE-----";


static enum _error_type {
    e_none,
    e_crypto,
    e_system,
    e_api
} error_type = e_none;

/**
 * @description: Used to decode url in cert
 * @param str -> Url
 * @return: Decoded url
 */
string url_decode(string str)
{
    string decoded;
    size_t i;
    size_t len = str.length();

    for (i = 0; i < len; ++i)
    {
        if (str[i] == '+')
            decoded += ' ';
        else if (str[i] == '%')
        {
            char *e = NULL;
            unsigned long int v;

            // Have a % but run out of characters in the string
            if (i + 3 > len)
                throw length_error("premature end of string");

            v = strtoul(str.substr(i + 1, 2).c_str(), &e, 16);

            // Have %hh but hh is not a valid hex code.
            if (*e)
                throw out_of_range("invalid encoding");

            decoded += static_cast<char>(v);
            i += 2;
        }
        else
            decoded += str[i];
    }

    return decoded;
}

/**
 * @description: Load cert
 * @param cert -> X509 certificate
 * @param pemdata -> PEM data
 * @param sz -> PEM data size
 * @return: Load status
 */
int cert_load_size(X509 **cert, const char *pemdata, size_t sz)
{
    BIO *bmem;
    error_type = e_none;

    bmem = BIO_new(BIO_s_mem());
    if (bmem == NULL)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (BIO_write(bmem, pemdata, (int)sz) != (int)sz)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    *cert = PEM_read_bio_X509(bmem, NULL, NULL, NULL);
    if (*cert == NULL)
        error_type = e_crypto;

cleanup:
    if (bmem != NULL)
        BIO_free(bmem);

    return (error_type == e_none);
}

/**
 * @description: Load cert based on data size
 * @param cert -> X509 certificate
 * @param pemdata -> PEM data
 * @return: Load status
 */
int cert_load(X509 **cert, const char *pemdata)
{
    return cert_load_size(cert, pemdata, strlen(pemdata));
}

/**
 * @description: Take an array of certificate pointers and build a stack.
 * @param certs -> Pointer to X509 certificate array
 * @return: x509 cert
 */
STACK_OF(X509) * cert_stack_build(X509 **certs)
{
    X509 **pcert;
    STACK_OF(X509) * stack;

    error_type = e_none;

    stack = sk_X509_new_null();
    if (stack == NULL)
    {
        error_type = e_crypto;
        return NULL;
    }

    for (pcert = certs; *pcert != NULL; ++pcert)
        sk_X509_push(stack, *pcert);

    return stack;
}

/**
 * @description: Verify cert chain against our CA in store. Assume the first cert in
 *   the chain is the one to validate. Note that a store context can only
 *   be used for a single verification so we need to do this every time
 *   we want to validate a cert.
 * @param store -> X509 store
 * @param chain -> X509 chain
 * @return: Verify status
 */
int cert_verify(X509_STORE *store, STACK_OF(X509) * chain)
{
    X509_STORE_CTX *ctx;
    X509 *cert = sk_X509_value(chain, 0);

    error_type = e_none;

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL)
    {
        error_type = e_crypto;
        return 0;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, chain) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (X509_verify_cert(ctx) != 1)
        error_type = e_crypto;

cleanup:
    if (ctx != NULL)
        X509_STORE_CTX_free(ctx);

    return (error_type == e_none);
}

/**
 * @description: Free cert stack
 * @param chain -> X509 chain
 */
void cert_stack_free(STACK_OF(X509) * chain)
{
    sk_X509_free(chain);
}

/**
 * @description: Verify content signature
 * @param msg -> Verified message
 * @param mlen -> Verified message length
 * @param sig -> Signature
 * @param sigsz -> Signature size
 * @param pkey -> EVP key
 * @return: Verify status
 */
int sha256_verify(const uint8_t *msg, size_t mlen, uint8_t *sig,
                  size_t sigsz, EVP_PKEY *pkey)
{
    EVP_MD_CTX *ctx;

    error_type = e_none;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, msg, mlen) != 1)
    {
        error_type = e_crypto;
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(ctx, sig, sigsz) != 1)
        error_type = e_crypto;

cleanup:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    return (error_type == e_none);
}

/**
 * @description: Init CA
 * @param cert -> X509 certificate
 * @return: x509 store
 */
X509_STORE *cert_init_ca(X509 *cert)
{
    X509_STORE *store;

    error_type = e_none;

    store = X509_STORE_new();
    if (store == NULL)
    {
        error_type = e_crypto;
        return NULL;
    }

    if (X509_STORE_add_cert(store, cert) != 1)
    {
        X509_STORE_free(store);
        error_type = e_crypto;
        return NULL;
    }

    return store;
}



/**
 * @description: Verify IAS report and upload identity
 * @param IASReport -> Pointer to vector address
 * @param size -> Vector size
 * @return: Verify status
 */
crust_status_t id_verify_and_upload_identity(char **IASReport, size_t size)
{
    string certchain;
    string certchain_1;
    size_t cstart, cend, count, i;
    X509 **certar;
    STACK_OF(X509) * stack;
    vector<X509 *> certvec;
    vector<string> messages;
    int rv;
    string ias_sig, header;
    size_t sigsz;
    X509 *sign_cert;
    EVP_PKEY *pkey = NULL;
    crust_status_t status = CRUST_SUCCESS;
    uint8_t *sig = NULL;
    string isv_body;
    int quoteSPos = 0;
    int quoteEPos = 0;
    size_t spos = 0;
    size_t epos = 0;
    string ias_quote_body;
    sgx_quote_t *iasQuote = NULL;
    sgx_report_body_t *iasReportBody;
    char *p_decode_quote_body = NULL;
    size_t qbsz;
    sgx_status_t sgx_status;
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_ec256_signature_t ecc_signature;

    json::JSON id_json;
    std::string id_str;

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, INTELSGXATTROOTCA);
    X509 *intelRootPemX509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    vector<string> response(IASReport, IASReport + size);

    Workload *wl = Workload::get_instance();
    string chain_account_id = wl->get_account_id();
    uint8_t *p_account_id_u = hex_string_to_bytes(chain_account_id.c_str(), chain_account_id.size());
    size_t account_id_u_len = chain_account_id.size() / 2;
    uint8_t *org_data, *p_org_data = NULL;
    uint32_t org_data_len = 0;


    // ----- Verify IAS signature ----- //

    /*
     * The response body has the attestation report. The headers have
     * a signature of the report, and the public signing certificate.
     * We need to:
     *
     * 1) Verify the certificate chain, to ensure it's issued by the
     *    Intel CA (passed with the -A option).
     *
     * 2) Extract the public key from the signing cert, and verify
     *    the signature.
     */

    // Get the certificate chain from the headers

    certchain = response[0];
    if (certchain == "")
    {
        return CRUST_IAS_BAD_CERTIFICATE;
    }

    // URL decode
    try
    {
        certchain = url_decode(certchain);
    }
    catch (...)
    {
        return CRUST_IAS_BAD_CERTIFICATE;
    }

    // Build the cert stack. Find the positions in the string where we
    // have a BEGIN block.

    cstart = cend = 0;
    while (cend != string::npos)
    {
        X509 *cert;
        size_t len;

        cend = certchain.find("-----BEGIN", cstart + 1);
        len = ((cend == string::npos) ? certchain.length() : cend) - cstart;

        if (certchain_1.size() == 0)
        {
            certchain_1 = certchain.substr(cstart, len);
        }

        if (!cert_load(&cert, certchain.substr(cstart, len).c_str()))
        {
            return CRUST_IAS_BAD_CERTIFICATE;
        }

        certvec.push_back(cert);
        cstart = cend;
    }

    count = certvec.size();

    certar = (X509 **)enc_malloc(sizeof(X509 *) * (count + 1));
    if (certar == NULL)
    {
        return CRUST_IAS_INTERNAL_ERROR;
    }
    for (i = 0; i < count; ++i)
        certar[i] = certvec[i];
    certar[count] = NULL;

    // Create a STACK_OF(X509) stack from our certs

    stack = cert_stack_build(certar);
    if (stack == NULL)
    {
        status = CRUST_IAS_INTERNAL_ERROR;
        goto cleanup;
    }

    // Now verify the signing certificate

    rv = cert_verify(cert_init_ca(intelRootPemX509), stack);

    if (!rv)
    {
        status = CRUST_IAS_BAD_CERTIFICATE;
        goto cleanup;
    }

    // The signing cert is valid, so extract and verify the signature

    ias_sig = response[1];
    if (ias_sig == "")
    {
        status = CRUST_IAS_BAD_SIGNATURE;
        goto cleanup;
    }

    sig = (uint8_t *)base64_decode(ias_sig.c_str(), &sigsz);
    if (sig == NULL)
    {
        status = CRUST_IAS_BAD_SIGNATURE;
        goto cleanup;
    }

    sign_cert = certvec[0]; /* The first cert in the list */

    /*
     * The report body is SHA256 signed with the private key of the
     * signing cert.  Extract the public key from the certificate and
     * verify the signature.
     */

    pkey = X509_get_pubkey(sign_cert);
    if (pkey == NULL)
    {
        status = CRUST_IAS_GETPUBKEY_FAILED;
        goto cleanup;
    }

    isv_body = response[2];

    // verify IAS signature
    if (!sha256_verify((const uint8_t *)isv_body.c_str(), isv_body.length(), sig, sigsz, pkey))
    {
        status = CRUST_IAS_BAD_SIGNATURE;
        goto cleanup;
    }
    else
    {
        status = CRUST_SUCCESS;
    }

    // Verify quote
    quoteSPos = (int)isv_body.find("\"" IAS_ISV_BODY_TAG "\":\"");
    quoteSPos = (int)isv_body.find("\":\"", quoteSPos) + 3;
    quoteEPos = (int)isv_body.size() - 2;
    ias_quote_body = isv_body.substr(quoteSPos, quoteEPos - quoteSPos);

    p_decode_quote_body = base64_decode(ias_quote_body.c_str(), &qbsz);
    if (p_decode_quote_body == NULL)
    {
        status = CRUST_IAS_BAD_BODY;
        goto cleanup;
    }

    iasQuote = (sgx_quote_t *)enc_malloc(sizeof(sgx_quote_t));
    if (iasQuote == NULL)
    {
        log_err("Malloc memory failed!\n");
        goto cleanup;
    }
    memset(iasQuote, 0, sizeof(sgx_quote_t));
    memcpy(iasQuote, p_decode_quote_body, qbsz);
    iasReportBody = &iasQuote->report_body;

    // This report data is our ecc public key
    // should be equal to the one contained in IAS report
    if (memcmp(iasReportBody->report_data.d, &wl->get_pub_key(), sizeof(sgx_ec256_public_t)) != 0)
    {
        status = CRUST_IAS_REPORTDATA_NE;
        goto cleanup;
    }

    // The mr_enclave should be equal to the one contained in IAS report
    if (memcmp(&iasReportBody->mr_enclave, &wl->get_mr_enclave(), sizeof(sgx_measurement_t)) != 0)
    {
        status = CRUST_IAS_BADMEASUREMENT;
        goto cleanup;
    }

    // ----- Sign IAS report with current private key ----- //
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }

    // Generate identity data for sig
    spos = certchain_1.find("-----BEGIN CERTIFICATE-----\n") + strlen("-----BEGIN CERTIFICATE-----\n");
    epos = certchain_1.find("\n-----END CERTIFICATE-----");
    certchain_1 = certchain_1.substr(spos, epos - spos);
    replace(certchain_1, "\n", "");
    org_data_len = certchain_1.size() 
        + ias_sig.size() 
        + isv_body.size() 
        + account_id_u_len;
    org_data = (uint8_t *)malloc(org_data_len);
    if (org_data == NULL)
    {
        log_err("Malloc memory failed!\n");
        goto cleanup;
    }
    memset(org_data, 0, org_data_len);
    p_org_data = org_data;

    memcpy(org_data, certchain_1.c_str(), certchain_1.size());
    org_data += certchain_1.size();
    memcpy(org_data, ias_sig.c_str(), ias_sig.size());
    org_data += ias_sig.size();
    memcpy(org_data, isv_body.c_str(), isv_body.size());
    org_data += isv_body.size();
    memcpy(org_data, p_account_id_u, account_id_u_len);

    sgx_status = sgx_ecdsa_sign(p_org_data, (uint32_t)org_data_len,
            const_cast<sgx_ec256_private_t *>(&wl->get_pri_key()), &ecc_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }
    
    // Get sworker identity and store it outside of sworker
    id_json[IAS_CERT] = certchain_1;
    id_json[IAS_SIG] = ias_sig;
    id_json[IAS_ISV_BODY] = isv_body;
    id_json[IAS_CHAIN_ACCOUNT_ID] = chain_account_id;
    id_json[IAS_REPORT_SIG] = hexstring_safe(&ecc_signature, sizeof(sgx_ec256_signature_t));
    id_str = id_json.dump();

    // Upload identity to chain
    ocall_upload_identity(&status, id_str.c_str());


cleanup:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    cert_stack_free(stack);

    if (certar != NULL)
        free(certar);

    for (i = 0; i < count; ++i)
    {
        X509_free(certvec[i]);
    }

    if (sig != NULL)
        free(sig);

    if (iasQuote != NULL)
        free(iasQuote);

    if (ecc_state != NULL)
        sgx_ecc256_close_context(ecc_state);

    if (p_org_data != NULL)
        free(p_org_data);

    if (p_decode_quote_body != NULL)
        free(p_decode_quote_body);

    if (p_account_id_u != NULL)
        free(p_account_id_u);

    return status;
}

/**
 * @description: Generate ecc key pair and store it in enclave
 * @param account_id (in) -> Pointer to account id
 * @param len -> Account id length
 * @return: Generate status
 */
sgx_status_t id_gen_key_pair(const char *account_id, size_t len)
{
    Workload *wl = Workload::get_instance();
    if (wl->try_get_key_pair())
    {
        log_err("Identity key pair has been generated!\n");
        return SGX_ERROR_UNEXPECTED;
    }

    if (account_id == NULL || 0 == len)
    {
        log_err("Invalid account id!\n");
        return SGX_ERROR_UNEXPECTED;
    }

    // Generate public and private key
    sgx_ec256_public_t pub_key;
    sgx_ec256_private_t pri_key;
    memset(&pub_key, 0, sizeof(pub_key));
    memset(&pri_key, 0, sizeof(pri_key));
    sgx_status_t se_ret;
    sgx_ecc_state_handle_t ecc_state = NULL;
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }
    se_ret = sgx_ecc256_create_key_pair(&pri_key, &pub_key, ecc_state);
    if (SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    // Store key pair in enclave
    ecc_key_pair tmp_key_pair;
    memcpy(&tmp_key_pair.pub_key, &pub_key, sizeof(sgx_ec256_public_t));
    memcpy(&tmp_key_pair.pri_key, &pri_key, sizeof(sgx_ec256_private_t));
    wl->set_key_pair(tmp_key_pair);

    // Set chain account id
    Workload::get_instance()->set_account_id(string(account_id, len));

    return SGX_SUCCESS;
}

/**
 * @description: Get sgx report, our generated public key contained
 *  in report data
 * @param report -> Sgx report
 * @param target_info -> Sgx target info
 * @return: Get sgx report status
 */
sgx_status_t id_get_quote_report(sgx_report_t *report, sgx_target_info_t *target_info)
{

    // Copy public key to report data
    Workload *wl = Workload::get_instance();
    sgx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    memcpy(&report_data, &wl->get_pub_key(), sizeof(sgx_ec256_public_t));
#ifdef SGX_HW_SIM
    return sgx_create_report(NULL, &report_data, report);
#else
    return sgx_create_report(target_info, &report_data, report);
#endif
}

/**
 * @description: Generate current code measurement
 * @return: Generate status
 */
sgx_status_t id_gen_sgx_measurement()
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_report_t verify_report;
    sgx_target_info_t verify_target_info;
    sgx_report_data_t verify_report_data;

    memset(&verify_report, 0, sizeof(sgx_report_t));
    memset(&verify_report_data, 0, sizeof(sgx_report_data_t));
    memset(&verify_target_info, 0, sizeof(sgx_target_info_t));

    status = sgx_create_report(&verify_target_info, &verify_report_data, &verify_report);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    Workload::get_instance()->set_mr_enclave(verify_report.body.mr_enclave);

    return status;
}

/**
 * @description: For store metadata, get metadata title buffer size
 * @return: Buffer size
 */
size_t id_get_metadata_title_size()
{
    Workload *wl = Workload::get_instance();
    return strlen(SWORKER_PRIVATE_TAG) + 5
           + strlen(ID_SRD) + 5
           + strlen(ID_KEY_PAIR) + 3 + 256 + 3
           + strlen(ID_REPORT_HEIGHT) + 3 + 20 + 1
           + strlen(ID_CHAIN_ACCOUNT_ID) + 3 + 64 + 3
           + (wl->is_upgrade() ? strlen(ID_PRE_PUB_KEY) + 3 + sizeof(wl->pre_pub_key) * 2 + 3 : 0)
           + strlen(ID_FILE) + 3;
}

/**
 * @description: Get srd buffer size
 * @param srd_hashs -> Reference to srd metedata
 * @return: Buffer size
 */
size_t id_get_srd_buffer_size(std::vector<uint8_t *> &srd_hashs)
{
    return srd_hashs.size() * (HASH_LENGTH * 2 + 3) + 10;
}

/**
 * @description: Get file buffer size
 * @param sealed_files -> Reference to file metedata
 * @return: Buffer size
 */
size_t id_get_file_buffer_size(std::vector<json::JSON> &sealed_files)
{
    size_t ret = strlen(FILE_CID) + 3 + CID_LENGTH + 3
               + strlen(FILE_HASH) + 3 + strlen(HASH_TAG) + HASH_LENGTH * 2 + 3
               + strlen(FILE_SIZE) + 3 + 12 + 1
               + strlen(FILE_SEALED_SIZE) + 3 + 12 + 1
               + strlen(FILE_BLOCK_NUM) + 3 + 6 + 1
               + strlen(FILE_CHAIN_BLOCK_NUM) + 3 + 32 + 1
               + strlen(FILE_STATUS) + 3 + 3 + 3
               + 2;

    ret = sealed_files.size() * ret;

    return ret;
}

/**
 * @description: Store metadata periodically
 * Just store all metadata except meaningful files.
 * @return: Store status
 */
crust_status_t id_store_metadata()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_SUCCESS;
    }

    SafeLock sl(g_metadata_mutex);
    sl.lock();

    // Get original metadata
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string hex_id_key_str = hexstring_safe(&wl->get_key_pair(), sizeof(ecc_key_pair));

    // Store workload spec info
    std::string wl_spec_info_str = wl->get_wl_spec().dump();
    remove_char(wl_spec_info_str, '\n');
    remove_char(wl_spec_info_str, '\\');
    remove_char(wl_spec_info_str, ' ');
    persist_set_unsafe(DB_WL_SPEC_INFO, reinterpret_cast<const uint8_t *>(wl_spec_info_str.c_str()), wl_spec_info_str.size());

    // ----- Calculate metadata volumn ----- //
    // Get srd data copy
    sgx_thread_mutex_lock(&wl->srd_mutex);
    std::vector<uint8_t *> srd_hashs;
    srd_hashs.insert(srd_hashs.end(), wl->srd_hashs.begin(), wl->srd_hashs.end());
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // Get file data copy
    sgx_thread_mutex_lock(&wl->file_mutex);
    std::vector<json::JSON> sealed_files;
    sealed_files.insert(sealed_files.end(), wl->sealed_files.begin(), wl->sealed_files.end());
    sgx_thread_mutex_unlock(&wl->file_mutex);
    
    // Get meta buffer
    size_t meta_len = id_get_srd_buffer_size(srd_hashs)
                    + id_get_file_buffer_size(sealed_files)
                    + id_get_metadata_title_size();
    uint8_t *meta_buf = (uint8_t *)enc_malloc(meta_len);
    if (meta_buf == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(meta_buf, 0, meta_len);
    size_t offset = 0;

    // ----- Store metadata ----- //
    // Append private data tag
    memcpy(meta_buf, SWORKER_PRIVATE_TAG, strlen(SWORKER_PRIVATE_TAG));
    offset += strlen(SWORKER_PRIVATE_TAG);
    memcpy(meta_buf + offset, "{", 1);
    offset += 1;

    // Append srd
    std::string wl_title;
    wl_title.append("\"").append(ID_SRD).append("\":[");
    memcpy(meta_buf + offset, wl_title.c_str(), wl_title.size());
    offset += wl_title.size();
    for (size_t i = 0; i < wl->srd_hashs.size(); i++)
    {
        std::string hash_str;
        hash_str.append("\"").append(hexstring_safe(wl->srd_hashs[i], HASH_LENGTH)).append("\"");
        memcpy(meta_buf + offset, hash_str.c_str(), hash_str.size());
        offset += hash_str.size();
        if (i != wl->srd_hashs.size() - 1)
        {
            memcpy(meta_buf + offset, ",", 1);
            offset += 1;
        }
    }
    memcpy(meta_buf + offset, "],", 2);
    offset += 2;
    // Append id key pair
    std::string key_pair_str;
    key_pair_str.append("\"").append(ID_KEY_PAIR).append("\":")
        .append("\"").append(hex_id_key_str).append("\",");
    memcpy(meta_buf + offset, key_pair_str.c_str(), key_pair_str.size());
    offset += key_pair_str.size();
    // Append report height
    std::string report_height_str;
    report_height_str.append("\"").append(ID_REPORT_HEIGHT).append("\":")
        .append(std::to_string(wl->get_report_height())).append(",");
    memcpy(meta_buf + offset, report_height_str.c_str(), report_height_str.size());
    offset += report_height_str.size();
    // Append chain account id
    std::string account_id_str;
    account_id_str.append("\"").append(ID_CHAIN_ACCOUNT_ID).append("\":")
        .append("\"").append(wl->get_account_id()).append("\",");
    memcpy(meta_buf + offset, account_id_str.c_str(), account_id_str.size());
    offset += account_id_str.size();
    // Append previous public key
    if (wl->is_upgrade())
    {
        std::string pre_pub_key_str;
        pre_pub_key_str.append("\"").append(ID_PRE_PUB_KEY).append("\":")
            .append("\"").append(hexstring_safe(&wl->pre_pub_key, sizeof(wl->pre_pub_key))).append("\",");
        memcpy(meta_buf + offset, pre_pub_key_str.c_str(), pre_pub_key_str.size());
        offset += pre_pub_key_str.size();
    }
    // Append files
    std::string file_title;
    file_title.append("\"").append(ID_FILE).append("\":[");
    memcpy(meta_buf + offset, file_title.c_str(), file_title.size());
    offset += file_title.size();
    for (size_t i = 0; i < sealed_files.size(); i++)
    {
        std::string file_str = sealed_files[i].dump();
        remove_char(file_str, '\n');
        remove_char(file_str, '\\');
        remove_char(file_str, ' ');
        memcpy(meta_buf + offset, file_str.c_str(), file_str.size());
        offset += file_str.size();
        if (i != sealed_files.size() - 1)
        {
            memcpy(meta_buf + offset, ",", 1);
            offset += 1;
        }
    }
    memcpy(meta_buf + offset, "]}", 2);
    offset += 2;

    crust_status = persist_set(ID_METADATA, meta_buf, offset);
    free(meta_buf);

    sl.unlock();

    return crust_status;
}

/**
 * @description: Restore enclave all metadata
 * @return: Restore status
 */
crust_status_t id_restore_metadata()
{
    Workload *wl = Workload::get_instance();

    SafeLock sl(g_metadata_mutex);
    sl.lock();
    // ----- Get metadata ----- //
    json::JSON meta_json;
    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = persist_get(ID_METADATA, &p_data, &data_len);
    if (CRUST_SUCCESS != crust_status)
    {
        log_warn("No metadata, this may be the first start\n");
        return CRUST_UNEXPECTED_ERROR;
    }
    meta_json = json::JSON::Load(p_data + strlen(SWORKER_PRIVATE_TAG), data_len);
    free(p_data);
    if (meta_json.size() == 0)
    {
        log_warn("Invalid metadata!\n");
        return CRUST_INVALID_META_DATA;
    }
    // Verify meta data
    std::string id_key_pair_str = meta_json[ID_KEY_PAIR].ToString();
    uint8_t *p_id_key = hex_string_to_bytes(id_key_pair_str.c_str(), id_key_pair_str.size());
    if (p_id_key == NULL)
    {
        log_err("Identity: Get id key pair failed!\n");
        return CRUST_INVALID_META_DATA;
    }
    if (wl->try_get_key_pair() && memcmp(p_id_key, &wl->get_key_pair(), sizeof(ecc_key_pair)) != 0)
    {
        free(p_id_key);
        log_err("Identity: Get wrong id key pair!\n");
        return CRUST_INVALID_META_DATA;
    }

    // ----- Restore metadata ----- //
    // Restore workload spec information
    uint8_t *p_wl_spec = NULL;
    size_t wl_spec_len = 0;
    if (CRUST_SUCCESS != (crust_status = persist_get_unsafe(DB_WL_SPEC_INFO, &p_wl_spec, &wl_spec_len)))
    {
        log_warn("Cannot get workload spec info, code:%lx\n", crust_status);
    }
    else if (p_wl_spec != NULL)
    {
        wl->restore_wl_spec_info(std::string(reinterpret_cast<const char *>(p_wl_spec), wl_spec_len));
        free(p_wl_spec);
    }
    // Restore srd
    if (meta_json.hasKey(ID_SRD)
            && meta_json[ID_SRD].JSONType() == json::JSON::Class::Array)
    {
        crust_status = wl->restore_srd(meta_json[ID_SRD]);
        if (CRUST_SUCCESS != crust_status)
        {
            return CRUST_BAD_SEAL_DATA;
        }
    }
    // Restore srd info
    std::string srd_info_str = wl->get_srd_info().dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, 
                    reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Wait for srd info, code:%lx\n", crust_status);
    }
    // Restore meaningful files
    if (meta_json.hasKey(ID_FILE)
            && meta_json[ID_FILE].JSONType() == json::JSON::Class::Array)
    {
        wl->sealed_files.resize(meta_json[ID_FILE].size());
        for (int i = 0; i < meta_json[ID_FILE].size(); i++)
        {
            wl->sealed_files[i] = meta_json[ID_FILE][i];
        }
        // Retore file info
        size_t file_info_len = (CID_LENGTH + 3 + strlen(FILE_SIZE) + 3 + 16 + 10) * wl->sealed_files.size() + 32;
        uint8_t *file_info_buf = (uint8_t *)enc_malloc(file_info_len);
        size_t file_info_offset = 0;
        memset(file_info_buf, 0, file_info_len);
        memcpy(file_info_buf, "{", 1);
        file_info_offset += 1;
        for (size_t i = 0; i < wl->sealed_files.size(); i++)
        {
            json::JSON file = wl->sealed_files[i];
            std::string info;
            info.append("\"").append(file[FILE_CID].ToString()).append("\":")
                .append("\"{ \\\"size\\\" : ").append(std::to_string(file[FILE_SIZE].ToInt())).append(" , ")
                .append("\\\"sealed_size\\\" : ").append(std::to_string(file[FILE_SEALED_SIZE].ToInt())).append(" , ")
                .append("\\\"block_number\\\" : ").append(std::to_string(file[FILE_CHAIN_BLOCK_NUM].ToInt())).append(" }\"");
            if (i != wl->sealed_files.size() - 1)
            {
                info.append(",");
            }
            memcpy(file_info_buf + file_info_offset, info.c_str(), info.size());
            file_info_offset += info.size();
        }
        memcpy(file_info_buf + file_info_offset, "}", 1);
        file_info_offset += 1;
        persist_set_unsafe(DB_FILE_INFO, file_info_buf, file_info_offset);
        free(file_info_buf);
    }
    // Restore id key pair
    ecc_key_pair tmp_key_pair;
    memcpy(&tmp_key_pair, p_id_key, sizeof(ecc_key_pair));
    wl->set_key_pair(tmp_key_pair);
    free(p_id_key);
    // Restore report height
    wl->set_report_height(meta_json[ID_REPORT_HEIGHT].ToInt());
    // Restore previous public key
    if (meta_json.hasKey(ID_PRE_PUB_KEY))
    {
        sgx_ec256_public_t pre_pub_key;
        std::string pre_pub_key_str = meta_json[ID_PRE_PUB_KEY].ToString();
        uint8_t *pre_pub_key_u = hex_string_to_bytes(pre_pub_key_str.c_str(), pre_pub_key_str.size());
        if (pre_pub_key_u == NULL)
        {
            return CRUST_UNEXPECTED_ERROR;
        }
        memcpy(&pre_pub_key, pre_pub_key_u, sizeof(sgx_ec256_public_t));
        free(pre_pub_key_u);
        wl->set_upgrade(pre_pub_key);
    }
    // Restore chain account id
    wl->set_account_id(meta_json[ID_CHAIN_ACCOUNT_ID].ToString());

    wl->set_restart_flag();

    return CRUST_SUCCESS;
}

/**
 * @description: Compare chain account with enclave's
 * @param account_id -> Pointer to account id
 * @param len -> account id length
 * @return: Compare status
 */
crust_status_t id_cmp_chain_account_id(const char *account_id, size_t len)
{
    Workload *wl = Workload::get_instance();
    if (memcmp(wl->get_account_id().c_str(), account_id, len) != 0)
    {
        return CRUST_NOT_EQUAL;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Show enclave id information
 */
void id_get_info()
{
    Workload *wl = Workload::get_instance();
    json::JSON id_info;
    id_info["pub_key"] = hexstring_safe(&wl->get_pub_key(), sizeof(sgx_ec256_public_t));
    id_info["mrenclave"] = hexstring_safe(&wl->get_mr_enclave(), sizeof(sgx_measurement_t));
    std::string id_str = id_info.dump();
    ocall_store_enclave_id_info(id_str.c_str());
}

/**
 * @description: Generate upgrade data
 * @param block_height -> Current block height
 * @return: Generate result
 */
crust_status_t id_gen_upgrade_data(size_t block_height)
{
    sgx_thread_mutex_lock(&g_gen_work_report);

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    json::JSON upgrade_json;
    Workload *wl = Workload::get_instance();
    sgx_ec256_signature_t sgx_sig; 
    sgx_ecc_state_handle_t ecc_state = NULL;
    std::string mr_str;
    std::string sig_str;
    std::string pubkey_data;
    std::string block_height_data;
    std::string block_hash_data;
    std::string srd_title;
    std::string files_title;
    std::string srd_root_data;
    std::string files_root_data;
    std::string sig_data;
    std::string report_height_str;
    uint8_t *p_files = NULL;
    uint8_t *p_srd = NULL;
    size_t files_size = 0;
    size_t srd_size = 0;
    uint8_t *sigbuf = NULL;
    uint8_t *p_sigbuf = NULL;
    size_t sigbuf_len = 0;
    char *report_hash = NULL;
    size_t report_height = 0;
    size_t upgrade_buffer_len = 0;
    uint8_t *upgrade_buffer = NULL;
    uint8_t *p_upgrade_buffer = NULL;
    json::JSON wl_info;
    size_t random_time = 0;

    // ----- Generate and upload work report ----- //
    // Current era has reported, wait for next era
    if (block_height <= wl->get_report_height())
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    if (block_height - wl->get_report_height() - WORKREPORT_REPORT_INTERVAL < ERA_LENGTH)
    {
        crust_status = CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
        goto cleanup;
    }
    report_height = wl->get_report_height();
    while (block_height - report_height > ERA_LENGTH)
    {
        report_height += ERA_LENGTH;
    }
    report_hash = (char *)enc_malloc(HASH_LENGTH * 2);
    if (report_hash == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(report_hash, 0, HASH_LENGTH * 2);
    ocall_get_block_hash(&crust_status, report_height, report_hash, HASH_LENGTH * 2);
    if (CRUST_SUCCESS != crust_status)
    {
        crust_status = CRUST_UPGRADE_GET_BLOCK_HASH_FAILED;
        goto cleanup;
    }
    // Send work report
    // Wait a random time:[10, 50] block time
    sgx_read_rand(reinterpret_cast<uint8_t *>(&random_time), sizeof(size_t));
    random_time = ((random_time % (UPGRADE_WAIT_BLOCK_MAX - UPGRADE_WAIT_BLOCK_MIN + 1)) + UPGRADE_WAIT_BLOCK_MIN) * BLOCK_TIME_BASE;
    log_info("Upgrade: Will generate and send work reort after %ld blocks...\n", random_time / BLOCK_TIME_BASE);
    if (CRUST_SUCCESS != (crust_status = gen_and_upload_work_report(report_hash, report_height, random_time, false, false)))
    {
        log_err("Fatal error! Send work report failed! Error code:%lx\n", crust_status);
        crust_status = CRUST_UPGRADE_GEN_WORKREPORT_FAILED;
        goto cleanup;
    }

    // ----- Generate upgrade data ----- //
    report_height_str = std::to_string(report_height);
    // Srd and files data
    crust_status = wl->serialize_srd(&p_srd, &srd_size);
    if (CRUST_SUCCESS != crust_status)
    {
        goto cleanup;
    }
    crust_status = wl->serialize_file(&p_files, &files_size);
    if (CRUST_SUCCESS != crust_status)
    {
        goto cleanup;
    }
    wl_info = wl->gen_workload_info();
    if (crust_status != CRUST_SUCCESS)
    {
        goto cleanup;
    }
    // Sign upgrade data
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }
    sigbuf_len = sizeof(sgx_ec256_public_t) 
        + report_height_str.size()
        + HASH_LENGTH * 2
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_sha256_hash_t);
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        log_err("Malloc memory failed!\n");
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
    // Pub key
    memcpy(sigbuf, &wl->get_pub_key(), sizeof(sgx_ec256_public_t));
    sigbuf += sizeof(sgx_ec256_public_t);
    // Block height
    memcpy(sigbuf, report_height_str.c_str(), report_height_str.size());
    sigbuf += report_height_str.size();
    // Block hash
    memcpy(sigbuf, report_hash, HASH_LENGTH * 2);
    sigbuf += (HASH_LENGTH * 2);
    // Srd root
    memcpy(sigbuf, wl_info[WL_SRD_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Files root
    memcpy(sigbuf, wl_info[WL_FILE_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len,
            const_cast<sgx_ec256_private_t *>(&wl->get_pri_key()), &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // ----- Get final upgrade data ----- //
    pubkey_data.append("{\"" UPGRADE_PUBLIC_KEY "\":")
        .append("\"").append(hexstring_safe(&wl->get_pub_key(), sizeof(sgx_ec256_public_t))).append("\"");
    block_height_data.append(",\"" UPGRADE_BLOCK_HEIGHT "\":").append(report_height_str);
    block_hash_data.append(",\"" UPGRADE_BLOCK_HASH "\":")
        .append("\"").append(report_hash, HASH_LENGTH * 2).append("\"");
    srd_title.append(",\"" UPGRADE_SRD "\":");
    files_title.append(",\"" UPGRADE_FILE "\":");
    srd_root_data.append(",\"" UPGRADE_SRD_ROOT "\":")
        .append("\"").append(wl_info[WL_SRD_ROOT_HASH].ToString()).append("\"");
    files_root_data.append(",\"" UPGRADE_FILE_ROOT "\":")
        .append("\"").append(wl_info[WL_FILE_ROOT_HASH].ToString()).append("\"");
    sig_data.append(",\"" UPGRADE_SIG "\":")
        .append("\"").append(hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t))).append("\"}");
    upgrade_buffer_len = pubkey_data.size()
        + block_height_data.size()
        + block_hash_data.size()
        + srd_title.size()
        + srd_size
        + files_title.size()
        + files_size
        + srd_root_data.size()
        + files_root_data.size()
        + sig_data.size();
    upgrade_buffer = (uint8_t *)enc_malloc(upgrade_buffer_len);
    if (upgrade_buffer == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(upgrade_buffer, 0, upgrade_buffer_len);
    p_upgrade_buffer = upgrade_buffer;
    // Public key
    memcpy(upgrade_buffer, pubkey_data.c_str(), pubkey_data.size());
    upgrade_buffer += pubkey_data.size();
    // BLock height
    memcpy(upgrade_buffer, block_height_data.c_str(), block_height_data.size());
    upgrade_buffer += block_height_data.size();
    // Block hash
    memcpy(upgrade_buffer, block_hash_data.c_str(), block_hash_data.size());
    upgrade_buffer += block_hash_data.size();
    // Srd
    memcpy(upgrade_buffer, srd_title.c_str(), srd_title.size());
    upgrade_buffer += srd_title.size();
    memcpy(upgrade_buffer, p_srd, srd_size);
    upgrade_buffer += srd_size;
    // Files
    memcpy(upgrade_buffer, files_title.c_str(), files_title.size());
    upgrade_buffer += files_title.size();
    memcpy(upgrade_buffer, p_files, files_size);
    upgrade_buffer += files_size;
    // Srd root
    memcpy(upgrade_buffer, srd_root_data.c_str(), srd_root_data.size());
    upgrade_buffer += srd_root_data.size();
    // Files root
    memcpy(upgrade_buffer, files_root_data.c_str(), files_root_data.size());
    upgrade_buffer += files_root_data.size();
    // Signature
    memcpy(upgrade_buffer, sig_data.c_str(), sig_data.size());
    upgrade_buffer += sig_data.size();

    // Store upgrade data
    store_large_data(p_upgrade_buffer, upgrade_buffer_len, ocall_store_upgrade_data, wl->ocall_upgrade_mutex);


cleanup:
    sgx_thread_mutex_unlock(&g_gen_work_report);

    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    if (p_sigbuf != NULL)
    {
        free(p_sigbuf);
    }

    if (p_upgrade_buffer != NULL)
    {
        free(p_upgrade_buffer);
    }

    if (report_hash != NULL)
    {
        free(report_hash);
    }

    if (CRUST_SUCCESS == crust_status)
    {
        wl->set_upgrade_status(ENC_UPGRADE_STATUS_SUCCESS);
    }

    return crust_status;
}

/**
 * @description: Restore workload from upgrade data
 * @param data -> Upgrade data per transfer
 * @param data_size -> Upgrade data size per transfer
 * @param total_size -> Upgrade data total size
 * @param transfer_end -> Indicate whether upgrade data transfer is end
 * @return: Restore status
 */
crust_status_t id_restore_from_upgrade(const char *data, size_t data_size, size_t total_size, bool transfer_end)
{
    if (g_upgrade_buffer_offset == 0)
    {
        g_upgrade_buffer = (uint8_t *)enc_malloc(total_size);
        if (g_upgrade_buffer == NULL)
        {
            return CRUST_MALLOC_FAILED;
        }
        memset(g_upgrade_buffer, 0, total_size);
    }
    memcpy(g_upgrade_buffer + g_upgrade_buffer_offset, data, data_size);
    g_upgrade_buffer_offset += data_size;
    if (!transfer_end)
    {
        return CRUST_UPGRADE_NEED_LEFT_DATA;
    }
    json::JSON upgrade_json = json::JSON::Load(reinterpret_cast<const uint8_t *>(g_upgrade_buffer), g_upgrade_buffer_offset);
    free(g_upgrade_buffer);
    g_upgrade_buffer = NULL;
    g_upgrade_buffer_offset = 0;

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    uint8_t p_result;
    uint8_t *sigbuf = NULL;
    uint8_t *p_sigbuf = NULL;
    size_t sigbuf_len = 0;
    sgx_ecc_state_handle_t ecc_state = NULL;
    Workload *wl = Workload::get_instance();
    sgx_ec256_signature_t sgx_wl_sig;
    sgx_ec256_public_t sgx_a_pub_key;
    json::JSON srd_json;
    json::JSON file_json;
    json::JSON wl_info;
    std::string file_str;
    std::string wl_sig;
    std::string upgrade_srd_root_str;
    std::string upgrade_files_root_str;
    uint8_t *wl_sig_u = NULL;
    std::string report_height_str = upgrade_json[UPGRADE_BLOCK_HEIGHT].ToString();
    std::string report_hash_str = upgrade_json[UPGRADE_BLOCK_HASH].ToString();
    std::string a_pub_key_str = upgrade_json[UPGRADE_PUBLIC_KEY].ToString();
    uint8_t *a_pub_key_u = hex_string_to_bytes(a_pub_key_str.c_str(), a_pub_key_str.size());
    if (a_pub_key_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    memcpy(&sgx_a_pub_key, a_pub_key_u, sizeof(sgx_ec256_public_t));
    free(a_pub_key_u);

    // ----- Restore workload ----- //
    // Restore srd
    if (CRUST_SUCCESS != wl->restore_srd(upgrade_json[UPGRADE_SRD]))
    {
        crust_status = CRUST_UPGRADE_RESTORE_SRD_FAILED;
        goto cleanup;
    }
    // Restore file
    wl->restore_file(upgrade_json[UPGRADE_FILE]);

    // ----- Verify workload signature ----- //
    wl_info = wl->gen_workload_info();
    wl_sig = upgrade_json[UPGRADE_SIG].ToString();
    sigbuf_len = sizeof(sgx_ec256_public_t) 
        + report_height_str.size()
        + report_hash_str.size()
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_sha256_hash_t);
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
    // A's public key
    memcpy(sigbuf, &sgx_a_pub_key, sizeof(sgx_ec256_public_t));
    sigbuf += sizeof(sgx_ec256_public_t);
    // Block height
    memcpy(sigbuf, report_height_str.c_str(), report_height_str.size());
    sigbuf += report_height_str.size();
    // Block hash
    memcpy(sigbuf, report_hash_str.c_str(), report_hash_str.size());
    sigbuf += report_hash_str.size();
    // Srd root
    memcpy(sigbuf, wl_info[WL_SRD_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Files root
    memcpy(sigbuf, wl_info[WL_FILE_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    // Verify signature
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }
    wl_sig_u = hex_string_to_bytes(wl_sig.c_str(), wl_sig.size());
    if (wl_sig_u == NULL)
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    memcpy(&sgx_wl_sig, wl_sig_u, sizeof(sgx_ec256_signature_t));
    free(wl_sig_u);
    sgx_status = sgx_ecdsa_verify(p_sigbuf, sigbuf_len, &sgx_a_pub_key, 
            &sgx_wl_sig, &p_result, ecc_state);
    if (SGX_SUCCESS != sgx_status || p_result != SGX_EC_VALID)
    {
        log_err("Verify workload failed!Error code:%lx, result:%d\n", sgx_status, p_result);
        crust_status = CRUST_SGX_VERIFY_SIG_FAILED;
        goto cleanup;
    }

    // Verify workload srd and file root hash
    upgrade_srd_root_str = upgrade_json[UPGRADE_SRD_ROOT].ToString();
    upgrade_files_root_str = upgrade_json[UPGRADE_FILE_ROOT].ToString();
    if (wl_info[WL_SRD_ROOT_HASH].ToString().compare(upgrade_srd_root_str) != 0)
    {
        log_err("Verify workload srd root hash failed!\n");
        crust_status = CRUST_UPGRADE_BAD_SRD;
        goto cleanup;
    }
    if (wl_info[WL_FILE_ROOT_HASH].ToString().compare(upgrade_files_root_str) != 0)
    {
        log_err("Verify workload file root hash failed!current hash:%s\n", wl_info[WL_FILE_ROOT_HASH].ToString().c_str());
        crust_status = CRUST_UPGRADE_BAD_FILE;
        goto cleanup;
    }

    // ----- Entry network ----- //
    wl->set_upgrade(sgx_a_pub_key);
    ocall_entry_network(&crust_status);
    if (CRUST_SUCCESS != crust_status)
    {
        goto cleanup;
    }

    // ----- Send current version's work report ----- //
    wl->report_add_validated_proof();
    if (CRUST_SUCCESS != (crust_status = gen_and_upload_work_report(report_hash_str.c_str(), std::atoi(report_height_str.c_str()), 0, true)))
    {
        goto cleanup;
    }


cleanup:
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

    if (p_sigbuf != NULL)
    {
        free(p_sigbuf);
    }

    return crust_status;
}
