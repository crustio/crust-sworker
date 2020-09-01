#include "Identity.h"
#include "Workload.h"
#include "Persistence.h"
#include "EJson.h"

using namespace std;

// Store crust account id
string g_chain_account_id;
// Current node public and private key pair
ecc_key_pair id_key_pair;
// Can only set crust account id once
bool g_is_set_account_id = false;
// Can only set crust account id once
bool g_is_set_id_key_pair = false;
// TODO:Indicate if entry network successful
bool g_is_entry_network = false;
// Current code measurement
sgx_measurement_t current_mr_enclave;
// Used to check current block head out-of-date
size_t report_slot = 0;
// Used to indicate whether it is the first report after restart
bool just_after_restart = 0;
// Protect metadata 
sgx_thread_mutex_t g_metadata_mutex = SGX_THREAD_MUTEX_INITIALIZER;

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
 * @description: base64 decode function
 * @param msg -> To be decoded message
 * @param sz -> Message size
 * @return: Decoded result
 */
char *base64_decode(const char *msg, size_t *sz)
{
    BIO *b64, *bmem;
    char *buf;
    size_t len = strlen(msg);

    buf = (char *)enc_malloc(len + 1);
    if (buf == NULL)
        return NULL;
    memset(buf, 0, len + 1);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf(msg, (int)len);

    BIO_push(b64, bmem);

    int rsz = BIO_read(b64, buf, (int)len);
    if (rsz == -1)
    {
        free(buf);
        return NULL;
    }

    *sz = rsz;

    BIO_free_all(bmem);

    return buf;
}

/**
 * @description: Verify IAS report
 * @param IASReport -> Pointer to vector address
 * @param size -> Vector size
 * @return: Verify status
 */
crust_status_t id_verify_iasreport(char **IASReport, size_t size)
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
    string ias_quote_body;
    sgx_quote_t *iasQuote;
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

    string chain_account_id = response[3];
    uint8_t *p_account_id_u = hex_string_to_bytes(chain_account_id.c_str(), chain_account_id.size());
    size_t account_id_u_len = chain_account_id.size() / 2;
    uint8_t *org_data, *p_org_data = NULL;
    size_t org_data_len = 0;


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
    if (memcmp(iasReportBody->report_data.d, &id_key_pair.pub_key, sizeof(id_key_pair.pub_key)) != 0)
    {
        status = CRUST_IAS_REPORTDATA_NE;
        goto cleanup;
    }

    // The mr_enclave should be equal to the one contained in IAS report
    if (memcmp(&iasReportBody->mr_enclave, &current_mr_enclave, sizeof(sgx_measurement_t)) != 0)
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
    org_data_len = certchain_1.size() + ias_sig.size() + isv_body.size() + account_id_u_len;
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
            &id_key_pair.pri_key, &ecc_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        status = CRUST_SIGN_PUBKEY_FAILED;
        goto cleanup;
    }
    
    // Get tee identity and store it outside of tee
    id_json[IAS_CERT] = certchain_1;
    id_json[IAS_SIG] = ias_sig;
    id_json[IAS_ISV_BODY] = isv_body;
    id_json[IAS_CHAIN_ACCOUNT_ID] = chain_account_id;
    id_json[IAS_REPORT_SIG] = hexstring_safe(&ecc_signature, sizeof(sgx_ec256_signature_t));
    id_str = id_json.dump();

    ocall_store_identity(id_str.c_str());


cleanup:
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }
    cert_stack_free(stack);
    free(certar);
    for (i = 0; i < count; ++i)
    {
        X509_free(certvec[i]);
    }

    free(sig);
    free(iasQuote);
    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }

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
 * @return: Generate status
 */
sgx_status_t id_gen_key_pair()
{
    if (g_is_set_id_key_pair)
    {
        log_err("Identity key pair has been generated!\n");
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
    memset(&id_key_pair.pub_key, 0, sizeof(id_key_pair.pub_key));
    memset(&id_key_pair.pri_key, 0, sizeof(id_key_pair.pri_key));
    memcpy(&id_key_pair.pub_key, &pub_key, sizeof(pub_key));
    memcpy(&id_key_pair.pri_key, &pri_key, sizeof(pri_key));

    g_is_set_id_key_pair = true;

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
    sgx_report_data_t report_data;
    memset(&report_data, 0, sizeof(report_data));
    memcpy(&report_data, &id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
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

    memset(&current_mr_enclave, 0, sizeof(sgx_measurement_t));
    memcpy(&current_mr_enclave, &verify_report.body.mr_enclave, sizeof(sgx_measurement_t));

    return status;
}

/**
 * @description: Get metadata
 * @param meta_json -> Reference to metadata json
 * @param locked -> Indicate whether lock current operation
 */
void id_get_metadata(json::JSON &meta_json, bool locked /*=true*/)
{
    if (locked)
        sgx_thread_mutex_lock(&g_metadata_mutex);

    uint8_t *p_data = NULL;
    size_t data_len = 0;
    uint8_t *p_id_key = NULL;
    std::string id_key_pair_str;
    crust_status_t crust_status = persist_get(ID_METADATA, &p_data, &data_len);
    if (CRUST_SUCCESS != crust_status || data_len == 0)
    {
        meta_json = json::JSON();
        goto cleanup;
    }
    meta_json = json::JSON::Load(std::string(reinterpret_cast<char*>(p_data + strlen(TEE_PRIVATE_TAG)), data_len));
    if (meta_json.size() == 0)
    {
        goto cleanup;
    }
    // Verify meta data
    id_key_pair_str = meta_json[ID_KEY_PAIR].ToString();
    p_id_key = hex_string_to_bytes(id_key_pair_str.c_str(), id_key_pair_str.size());
    if (p_id_key == NULL)
    {
        log_err("Identity: Get id key pair failed!\n");
        crust_status = CRUST_INVALID_META_DATA;
        goto cleanup;
    }
    if (g_is_set_id_key_pair && memcmp(p_id_key, &id_key_pair, sizeof(id_key_pair)) != 0)
    {
        log_err("Identity: Get wrong id key pair!\n");
        crust_status = CRUST_INVALID_META_DATA;
        goto cleanup;
    }

cleanup:

    if (p_id_key != NULL)
        free(p_id_key);

    if (p_data != NULL)
        free(p_data);

    if (locked)
        sgx_thread_mutex_unlock(&g_metadata_mutex);

    return;
}

/**
 * @description: Set old matadata by new key values in meta_json
 * @param meta_json -> New metadata json to be set
 * @return: Set status
 */
crust_status_t id_metadata_set_by_new(json::JSON meta_json)
{
    sgx_thread_mutex_lock(&g_metadata_mutex);

    json::JSON meta_json_org;
    std::string meta_str;
    size_t meta_len = 0;
    uint8_t *p_meta = NULL;
    crust_status_t crust_status = CRUST_SUCCESS;
    id_get_metadata(meta_json_org, false);
    for (auto it : meta_json.ObjectRange())
    {
        meta_json_org[it.first] = it.second;
    }

    meta_str = meta_json_org.dump();
    meta_len = meta_str.size() + strlen(TEE_PRIVATE_TAG);
    p_meta = (uint8_t*)enc_malloc(meta_len);
    if (p_meta == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(p_meta, 0, meta_len);
    memcpy(p_meta, TEE_PRIVATE_TAG, strlen(TEE_PRIVATE_TAG));
    memcpy(p_meta + strlen(TEE_PRIVATE_TAG), meta_str.c_str(), meta_str.size());
    crust_status = persist_set(ID_METADATA, p_meta, meta_len);
    free(p_meta);

cleanup:
    sgx_thread_mutex_unlock(&g_metadata_mutex);

    return crust_status;
}

/**
 * @description: Get metadata by key
 * @param key -> Key
 * @return: Value
 */
json::JSON id_metadata_get_by_key(std::string key)
{
    sgx_thread_mutex_lock(&g_metadata_mutex);

    json::JSON meta_json_org;
    json::JSON val_json;
    id_get_metadata(meta_json_org, false);
    if (!meta_json_org.hasKey(key))
    {
        goto cleanup;
    }

    val_json = meta_json_org[key];

cleanup:
    sgx_thread_mutex_unlock(&g_metadata_mutex);

    return val_json;
}

/**
 * @description: Delete new file by file hash
 * @param file_hash -> To be deleted file hash
 * @return: Delete status
 */
crust_status_t id_metadata_del_by_key(std::string key)
{
    sgx_thread_mutex_lock(&g_metadata_mutex);

    crust_status_t crust_status = CRUST_SUCCESS;
    json::JSON meta_json_org;
    std::string meta_str;
    size_t meta_len = 0;
    uint8_t *p_meta = NULL;
    id_get_metadata(meta_json_org, false);
    auto p_obj = meta_json_org.ObjectRange();
    if (!meta_json_org.hasKey(key))
    {
        goto cleanup;
    }
    p_obj.object->erase(key);

    meta_str = meta_json_org.dump();
    meta_len = meta_str.size() + strlen(TEE_PRIVATE_TAG);
    p_meta = (uint8_t*)enc_malloc(meta_len);
    if (p_meta == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(p_meta, 0, meta_len);
    memcpy(p_meta, TEE_PRIVATE_TAG, strlen(TEE_PRIVATE_TAG));
    memcpy(p_meta + strlen(TEE_PRIVATE_TAG), meta_str.c_str(), meta_str.size());
    crust_status = persist_set(ID_METADATA, p_meta, meta_len);
    free(p_meta);

cleanup:
    sgx_thread_mutex_unlock(&g_metadata_mutex);

    return crust_status;
}

/**
 * @description: Store metadata periodically
 * Just store all metadata except meaningful files. Meaningfule files can be added through 
 * 'id_metadata_set_or_append' function
 * @return: Store status
 */
crust_status_t id_store_metadata()
{
    sgx_thread_mutex_lock(&g_metadata_mutex);

    // Get original metadata
    crust_status_t crust_status = CRUST_SUCCESS;
    json::JSON meta_json;
    size_t meta_len = 0;
    uint8_t *p_meta = NULL;
    std::string hex_id_key_str = hexstring_safe(&id_key_pair, sizeof(id_key_pair));
    id_get_metadata(meta_json, false);

    // ----- Store metadata ----- //
    meta_json[ID_WORKLOAD] = Workload::get_instance()->serialize_srd();
    meta_json[ID_KEY_PAIR] = hex_id_key_str;
    meta_json[ID_REPORT_SLOG] = report_slot;
    meta_json[ID_CHAIN_ACCOUNT_ID] = g_chain_account_id;
    std::string meta_str = meta_json.dump();
    meta_len = meta_str.size() + strlen(TEE_PRIVATE_TAG);
    p_meta = (uint8_t*)enc_malloc(meta_len);
    if (p_meta == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(p_meta, 0, meta_len);
    memcpy(p_meta, TEE_PRIVATE_TAG, strlen(TEE_PRIVATE_TAG));
    memcpy(p_meta + strlen(TEE_PRIVATE_TAG), meta_str.c_str(), meta_str.size());
    crust_status = persist_set(ID_METADATA, p_meta, meta_len);


cleanup:

    if (p_meta != NULL)
        free(p_meta);

    sgx_thread_mutex_unlock(&g_metadata_mutex);

    return crust_status;
}

/**
 * @description: Restore enclave all metadata
 * @return: Restore status
 */
crust_status_t id_restore_metadata()
{
    // Get metadata
    json::JSON meta_json;
    crust_status_t crust_status = CRUST_SUCCESS;
    id_get_metadata(meta_json);
    if (meta_json.size() <= 0)
    {
        log_warn("No metadata, this may be the first start\n");
        return CRUST_UNEXPECTED_ERROR;
    }

    // Restore srd
    Workload *wl = Workload::get_instance();
    if (meta_json.hasKey(ID_WORKLOAD)
            && meta_json[ID_WORKLOAD].JSONType() == json::JSON::Class::Object)
    {
        crust_status = wl->restore_srd(meta_json[ID_WORKLOAD]);
        if (CRUST_SUCCESS != crust_status)
        {
            return CRUST_BAD_SEAL_DATA;
        }
    }
    // Restore srd info
    ocall_srd_info_lock();
    json::JSON srd_info_json;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_info_json[it.first]["assigned"] = it.second.size();
    }
    std::string srd_info_str = srd_info_json.dump();
    if (CRUST_SUCCESS != (crust_status = persist_set_unsafe(DB_SRD_INFO, 
                    reinterpret_cast<const uint8_t *>(srd_info_str.c_str()), srd_info_str.size())))
    {
        log_warn("Wait for srd info, code:%lx\n", crust_status);
    }
    ocall_srd_info_unlock();
    // Restore meaningful files
    wl->checked_files.clear();
    if (meta_json.hasKey(ID_FILE)
            && meta_json[ID_FILE].JSONType() == json::JSON::Class::Array)
    {
        json::JSON m_files = meta_json[ID_FILE];
        for (int i = 0; i < m_files.size(); i++)
        {
            wl->checked_files.push_back(m_files[i]);
        }
    }
    // Restore id key pair
    std::string id_key_pair_str = meta_json[ID_KEY_PAIR].ToString();
    uint8_t *p_id_key = hex_string_to_bytes(id_key_pair_str.c_str(), id_key_pair_str.size());
    if (p_id_key == NULL)
    {
        log_err("Identity: restore metadata failed!\n");
        return CRUST_UNEXPECTED_ERROR;
    }
    memcpy(&id_key_pair, p_id_key, sizeof(id_key_pair));
    free(p_id_key);
    // Restore report slot
    report_slot = meta_json[ID_REPORT_SLOG].ToInt();
    // Restore chain account id
    g_chain_account_id = meta_json[ID_CHAIN_ACCOUNT_ID].ToString();

    g_is_set_id_key_pair = true;
    g_is_set_account_id = true;
    just_after_restart = true; 

    // Show workload
    std::string wl_str = wl->get_workload();
    replace(wl_str, "\"{", "{");
    replace(wl_str, "}\"", "  }");
    remove_char(wl_str, '\\');
    log_info("Workload:\n%s\n", wl_str.c_str());

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
    if (memcmp(g_chain_account_id.c_str(), account_id, len) != 0)
    {
        return CRUST_NOT_EQUAL;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Set crust account id
 * @param account_id -> Chain account id
 * @param len -> Chain account id length
 * @return: Set status
 */
crust_status_t id_set_chain_account_id(const char *account_id, size_t len)
{
    // Check if value has been set
    if (g_is_set_account_id)
    {
        return CRUST_DOUBLE_SET_VALUE;
    }

    char *buffer = (char *)enc_malloc(len);
    if (buffer == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(buffer, 0, len);
    memcpy(buffer, account_id, len);
    g_chain_account_id = string(buffer, len);
    g_is_set_account_id = true;

    return CRUST_SUCCESS;
}

/**
 * @description: Get key pair
 * @return: Identity key pair
 */
ecc_key_pair id_get_key_pair()
{
    return id_key_pair;
}

/**
 * @description: Get current work report slot
 * @return: Current work report slot
 */
size_t id_get_report_slot()
{
    return report_slot;
}

/**
 * @description: Set current work report slot
 * @param new_report_slot -> new report slot
 */
void id_set_report_slot(size_t new_report_slot)
{
    report_slot = new_report_slot;
    id_metadata_set_or_append(ID_REPORT_SLOG, std::to_string(report_slot));
}

/**
 * @description: Determine if it just restarted 
 * @return: true or false
 */
bool id_just_after_restart()
{
    return just_after_restart;
}

/**
 * @description: set just_after_restart
 * @param: true or false
 */
void id_set_just_after_restart(bool in)
{
    just_after_restart = in;
}

/**
 * @description: Show enclave id information
 */
void id_get_info()
{
    json::JSON id_info;
    id_info["pub_key"] = hexstring_safe(&id_key_pair.pub_key, sizeof(id_key_pair.pub_key));
    id_info["mrenclave"] = hexstring_safe(&current_mr_enclave, sizeof(sgx_measurement_t));
    std::string id_str = id_info.dump();
    ocall_store_enclave_id_info(id_str.c_str());
}
