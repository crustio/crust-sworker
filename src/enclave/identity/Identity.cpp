#include "Identity.h"
#include "Workload.h"
#include "Persistence.h"
#include "EJson.h"
#include "Report.h"

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
size_t g_report_height = 0;
// Used to indicate whether it is the first report after restart
bool just_after_restart = 0;
// Protect metadata 
sgx_thread_mutex_t g_metadata_mutex = SGX_THREAD_MUTEX_INITIALIZER;
// Upgrade generate metadata 
sgx_thread_mutex_t g_gen_work_report = SGX_THREAD_MUTEX_INITIALIZER;
// Upgrade buffer
uint8_t *g_upgrade_buffer = NULL;
size_t g_upgrade_buffer_offset = 0;

extern sgx_thread_mutex_t g_srd_mutex;
extern sgx_thread_mutex_t g_checked_files_mutex;

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

    string chain_account_id = g_chain_account_id;
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
    
    // Get sworker identity and store it outside of sworker
    id_json[IAS_CERT] = certchain_1;
    id_json[IAS_SIG] = ias_sig;
    id_json[IAS_ISV_BODY] = isv_body;
    id_json[IAS_CHAIN_ACCOUNT_ID] = chain_account_id;
    id_json[IAS_REPORT_SIG] = hexstring_safe(&ecc_signature, sizeof(sgx_ec256_signature_t));
    id_str = id_json.dump();

    ocall_store_identity(id_str.c_str());


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

    // Set chain account id
    crust_status_t crust_status = id_set_chain_account_id(account_id, len);
    if (crust_status != CRUST_SUCCESS)
    {
        log_err("Set chain account id error: %d\n", crust_status);
        return SGX_ERROR_UNEXPECTED;
    }

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
    meta_json = json::JSON::Load(p_data + strlen(SWORKER_PRIVATE_TAG), data_len);
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
 * @description: Store metadata periodically
 * Just store all metadata except meaningful files. Meaningfule files can be added through 
 * 'id_metadata_set_or_append' function
 * @return: Store status
 */
crust_status_t id_store_metadata()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return CRUST_SUCCESS;
    }

    sgx_thread_mutex_lock(&g_metadata_mutex);

    // Get original metadata
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string hex_id_key_str = hexstring_safe(&id_key_pair, sizeof(id_key_pair));

    // Calculate metadata volumn
    size_t meta_len = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        meta_len += it.second.size() * (64 + 3);
    }
    meta_len += wl->srd_path2hashs_m.size() * (128 + 4);
    meta_len += strlen(SWORKER_PRIVATE_TAG) + 5
        + strlen(ID_WORKLOAD) + 5
        + strlen(ID_KEY_PAIR) + 3 + 256 + 3
        + strlen(ID_REPORT_HEIGHT) + 3 + 20 + 1
        + strlen(ID_CHAIN_ACCOUNT_ID) + 3 + 64 + 3
        + (wl->is_upgrade() ? strlen(ID_PRE_PUB_KEY) + 3 + sizeof(wl->pre_pub_key) * 2 + 3 : 0)
        + strlen(ID_FILE) + 3;
    size_t file_item_len = strlen(FILE_HASH) + 3 + strlen(HASH_TAG) + 64 + 3
        + strlen(FILE_OLD_HASH) + 3 + strlen(HASH_TAG) + 64 + 3
        + strlen(FILE_SIZE) + 3 + 12 + 1
        + strlen(FILE_OLD_SIZE) + 3 + 12 + 1
        + strlen(FILE_BLOCK_NUM) + 3 + 6 + 1
        + strlen(FILE_STATUS) + 3 + 3 + 3
        + 2;
    meta_len += wl->checked_files.size() * file_item_len;
    uint8_t *meta_buf = (uint8_t *)enc_malloc(meta_len);
    if (meta_buf == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(meta_buf, 0, meta_len);
    size_t offset = 0;

    // ----- Store metadata ----- //
    memcpy(meta_buf, SWORKER_PRIVATE_TAG, strlen(SWORKER_PRIVATE_TAG));
    offset += strlen(SWORKER_PRIVATE_TAG);
    memcpy(meta_buf + offset, "{", 1);
    offset += 1;
    // Append srd
    std::string wl_title;
    wl_title.append("\"").append(ID_WORKLOAD).append("\":{");
    memcpy(meta_buf + offset, wl_title.c_str(), wl_title.size());
    offset += wl_title.size();
    size_t i = 0;
    for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++, i++)
    {
        std::string path_title;
        path_title.append("\"").append(it->first).append("\":[");
        memcpy(meta_buf + offset, path_title.c_str(), path_title.size());
        offset += path_title.size();
        for (size_t j = 0; j < it->second.size(); j++)
        {
            std::string hash_str;
            hash_str.append("\"").append(hexstring_safe(it->second[j], HASH_LENGTH)).append("\"");
            memcpy(meta_buf + offset, hash_str.c_str(), hash_str.size());
            offset += hash_str.size();
            if (j != it->second.size() - 1)
            {
                memcpy(meta_buf + offset, ",", 1);
                offset += 1;
            }
        }
        memcpy(meta_buf + offset, "]", 1);
        offset += 1;
        if (i != wl->srd_path2hashs_m.size() - 1)
        {
            memcpy(meta_buf + offset, ",", 1);
            offset += 1;
        }
    }
    memcpy(meta_buf + offset, "},", 2);
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
        .append(std::to_string(id_get_report_height())).append(",");
    memcpy(meta_buf + offset, report_height_str.c_str(), report_height_str.size());
    offset += report_height_str.size();
    // Append chain account id
    std::string account_id_str;
    account_id_str.append("\"").append(ID_CHAIN_ACCOUNT_ID).append("\":")
        .append("\"").append(g_chain_account_id).append("\",");
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
    for (size_t i = 0; i < wl->checked_files.size(); i++)
    {
        std::string file_str = wl->checked_files[i].dump();
        remove_char(file_str, '\n');
        remove_char(file_str, '\\');
        remove_char(file_str, ' ');
        memcpy(meta_buf + offset, file_str.c_str(), file_str.size());
        offset += file_str.size();
        if (i != wl->checked_files.size() - 1)
        {
            memcpy(meta_buf + offset, ",", 1);
            offset += 1;
        }
    }
    memcpy(meta_buf + offset, "]}", 2);
    offset += 2;

    crust_status = persist_set(ID_METADATA, meta_buf, offset);
    free(meta_buf);

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
        wl->checked_files.resize(meta_json[ID_FILE].size());
        for (int i = 0; i < meta_json[ID_FILE].size(); i++)
        {
            wl->checked_files[i] = meta_json[ID_FILE][i];
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
    id_set_report_height(meta_json[ID_REPORT_HEIGHT].ToInt());
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
    g_chain_account_id = meta_json[ID_CHAIN_ACCOUNT_ID].ToString();

    g_is_set_id_key_pair = true;
    g_is_set_account_id = true;
    just_after_restart = true; 

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

    if (account_id == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }

    g_chain_account_id = string(account_id, len);
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
 * @description: Get last report height
 * @return: Last report height
 */
size_t id_get_report_height()
{
    return g_report_height;
}

/**
 * @description: Set current report height
 * @param height -> new report height
 */
void id_set_report_height(size_t height)
{
    g_report_height = height;
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
    std::string work_report;
    std::string srd_str;
    std::string mr_str;
    std::string sig_str;
    std::string wr_title;
    std::string srd_title;
    std::string files_title;
    std::string srd_root_title;
    std::string files_root_title;
    std::string mr_title;
    std::string sig_title;
    uint8_t *p_files = NULL;
    size_t files_size = 0;
    uint8_t *sigbuf = NULL;
    uint8_t *p_sigbuf = NULL;
    size_t sigbuf_len = 0;
    char *report_hash = NULL;
    size_t report_height = 0;
    size_t upgrade_buffer_len = 0;
    uint8_t *upgrade_buffer = NULL;
    uint8_t *p_upgrade_buffer = NULL;
    json::JSON wl_info;

    // ----- Generate work report ----- //
    // Current era has reported, wait for next era
    if (block_height <= id_get_report_height())
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    if (block_height - id_get_report_height() - WORKREPORT_REPORT_INTERVAL < ERA_LENGTH)
    {
        crust_status = CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
        goto cleanup;
    }
    report_height = id_get_report_height();
    while (block_height - report_height > ERA_LENGTH)
    {
        report_height += ERA_LENGTH;
    }
    // Start upgrade process
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
    if (CRUST_SUCCESS != (crust_status = get_signed_work_report(report_hash, report_height, false)))
    {
        log_err("Fatal error! Get signed work report failed! Error code:%lx\n", crust_status);
        crust_status = CRUST_UPGRADE_GEN_WORKREPORT_FAILED;
        goto cleanup;
    }
    work_report = get_generated_work_report();
    work_report = json::JSON::Load(work_report).dump();
    remove_char(work_report, '\n');
    remove_char(work_report, '\\');
    remove_char(work_report, ' ');

    // Generate metadata
    wl->serialize_srd(srd_str);
    crust_status = wl->serialize_file(&p_files, &files_size);
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
    sigbuf_len = work_report.size() 
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_measurement_t);
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        log_err("Malloc memory failed!\n");
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
    // Work report
    memcpy(sigbuf, work_report.c_str(), work_report.size());
    sigbuf += work_report.size();
    // Srd root
    memcpy(sigbuf, wl_info[WL_SRD_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Files root
    memcpy(sigbuf, wl_info[WL_FILE_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // MR enclave
    memcpy(sigbuf, &current_mr_enclave, sizeof(sgx_measurement_t));
    sgx_status = sgx_ecdsa_sign(p_sigbuf, sigbuf_len, &id_key_pair.pri_key, &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }

    // ----- Store upgrade data ----- //
    wr_title.append("{\"" UPGRADE_WORK_REPORT "\":").append(work_report);
    srd_title.append(",\"" UPGRADE_SRD "\":");
    files_title.append(",\"" UPGRADE_FILE "\":");
    srd_root_title.append(",\"" UPGRADE_SRD_ROOT "\":")
        .append("\"").append(wl_info[WL_SRD_ROOT_HASH].ToString()).append("\"");
    files_root_title.append(",\"" UPGRADE_FILE_ROOT "\":")
        .append("\"").append(wl_info[WL_FILE_ROOT_HASH].ToString()).append("\"");
    mr_title.append(",\"" UPGRADE_MRENCLAVE "\":")
        .append("\"").append(hexstring_safe(&current_mr_enclave, sizeof(sgx_measurement_t))).append("\"");
    sig_title.append(",\"" UPGRADE_SIG "\":")
        .append("\"").append(hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t))).append("\"}");
    upgrade_buffer_len = srd_str.size()
        + files_size
        + wr_title.size()
        + srd_title.size()
        + files_title.size()
        + srd_root_title.size()
        + files_root_title.size()
        + mr_title.size()
        + sig_title.size();
    upgrade_buffer = (uint8_t *)enc_malloc(upgrade_buffer_len);
    if (upgrade_buffer == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(upgrade_buffer, 0, upgrade_buffer_len);
    p_upgrade_buffer = upgrade_buffer;
    // Work report
    memcpy(upgrade_buffer, wr_title.c_str(), wr_title.size());
    upgrade_buffer += wr_title.size();
    // Srd
    memcpy(upgrade_buffer, srd_title.c_str(), srd_title.size());
    upgrade_buffer += srd_title.size();
    memcpy(upgrade_buffer, srd_str.c_str(), srd_str.size());
    upgrade_buffer += srd_str.size();
    // Files
    memcpy(upgrade_buffer, files_title.c_str(), files_title.size());
    upgrade_buffer += files_title.size();
    memcpy(upgrade_buffer, p_files, files_size);
    upgrade_buffer += files_size;
    // Srd root
    memcpy(upgrade_buffer, srd_root_title.c_str(), srd_root_title.size());
    upgrade_buffer += srd_root_title.size();
    // Files root
    memcpy(upgrade_buffer, files_root_title.c_str(), files_root_title.size());
    upgrade_buffer += files_root_title.size();
    // MR_enclave
    memcpy(upgrade_buffer, mr_title.c_str(), mr_title.size());
    upgrade_buffer += mr_title.size();
    // Signature
    memcpy(upgrade_buffer, sig_title.c_str(), sig_title.size());
    upgrade_buffer += sig_title.size();

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
 * @param data -> Upgrade data
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
    json::JSON wr_json = upgrade_json[UPGRADE_WORK_REPORT];
    std::string work_report = upgrade_json[UPGRADE_WORK_REPORT].dump();
    remove_char(work_report, '\n');
    remove_char(work_report, '\\');
    remove_char(work_report, ' ');

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    uint8_t p_result;
    uint8_t *sigbuf = NULL;
    uint8_t *p_sigbuf = NULL;
    size_t sigbuf_len = 0;
    uint8_t *pub_key_u = NULL;
    size_t pub_key_u_len = 0;
    uint8_t *pre_pub_key_u = NULL;
    size_t pre_pub_key_u_len = 0;
    sgx_ecc_state_handle_t ecc_state = NULL;
    Workload *wl = Workload::get_instance();
    sgx_ec256_signature_t sgx_wr_sig;
    sgx_ec256_signature_t sgx_wl_sig;
    sgx_ec256_public_t sgx_pub_key;
    json::JSON srd_json;
    json::JSON file_json;
    json::JSON wl_info;
    std::string srd_str;
    std::string file_str;
    std::string mrenclave_str;
    std::string wl_sig;
    std::string upgrade_srd_root_str;
    std::string upgrade_files_root_str;
    uint8_t *mrenclave_u = NULL;
    uint8_t *wr_sig_u = NULL;
    uint8_t *wl_sig_u = NULL;

    // ----- Verify work report signature ----- //
    if (wr_json.size() <= 0)
    {
        return CRUST_UPGRADE_INVALID_WORKREPORT;
    }
    std::string wr_sig = wr_json[WORKREPORT_SIG].ToString();
    std::string pub_key_str = wr_json[WORKREPORT_PUB_KEY].ToString();
    std::string pre_pub_key_str = wr_json[WORKREPORT_PRE_PUB_KEY].ToString();
    std::string block_height_str = wr_json[WORKREPORT_BLOCK_HEIGHT].ToString();
    std::string block_hash_str = wr_json[WORKREPORT_BLOCK_HASH].ToString();
    std::string reserved = wr_json[WORKREPORT_RESERVED].ToString();
    std::string files_size_str = wr_json[WORKREPORT_FILES_SIZE].ToString();
    std::string srd_root_str = wr_json[WORKREPORT_RESERVED_ROOT].ToString();
    std::string files_root_str = wr_json[WORKREPORT_FILES_ROOT].ToString();
    std::string files_added = wr_json[WORKREPORT_FILES_ADDED].dump();
    std::string files_deleted = wr_json[WORKREPORT_FILES_DELETED].dump();
    remove_char(files_deleted, '\\');
    remove_char(files_deleted, '\n');
    remove_char(files_deleted, ' ');
    remove_char(files_added, '\\');
    remove_char(files_added, '\n');
    remove_char(files_added, ' ');
    sigbuf_len = sizeof(sgx_ec256_public_t) 
        + pre_pub_key_str.size() / 2
        + block_height_str.size()
        + HASH_LENGTH
        + reserved.size()
        + files_size_str.size()
        + sizeof(sgx_sha256_hash_t)
        + sizeof(sgx_sha256_hash_t)
        + files_added.size()
        + files_deleted.size();
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
    // Pub key
    pub_key_u = hex_string_to_bytes(pub_key_str.c_str(), pub_key_str.size());
    pub_key_u_len = pub_key_str.size() / 2;
    memcpy(sigbuf, pub_key_u, pub_key_u_len);
    sigbuf += pub_key_u_len;
    memcpy(&sgx_pub_key, pub_key_u, sizeof(sgx_ec256_public_t));
    free(pub_key_u);
    // Previous pub key
    pre_pub_key_u = hex_string_to_bytes(pre_pub_key_str.c_str(), pre_pub_key_str.size());
    if (pre_pub_key_u != NULL)
    {
        pre_pub_key_u_len = pre_pub_key_str.size() / 2;
        memcpy(sigbuf, pre_pub_key_u, pre_pub_key_u_len);
        sigbuf += pre_pub_key_u_len;
        free(pre_pub_key_u);
    }
    // Block height
    memcpy(sigbuf, block_height_str.c_str(), block_height_str.size());
    sigbuf += block_height_str.size();
    // Block hash
    uint8_t *block_hash_u = hex_string_to_bytes(block_hash_str.c_str(), block_hash_str.size());
    size_t block_hash_u_len = block_hash_str.size() / 2;
    memcpy(sigbuf, block_hash_u, block_hash_u_len);
    sigbuf += block_hash_u_len;
    free(block_hash_u);
    // Reserved
    memcpy(sigbuf, reserved.c_str(), reserved.size());
    sigbuf += reserved.size();
    // Files size
    memcpy(sigbuf, files_size_str.c_str(), files_size_str.size());
    sigbuf += files_size_str.size();
    // Reserved root
    uint8_t *srd_root_u = hex_string_to_bytes(srd_root_str.c_str(), srd_root_str.size());
    size_t srd_root_u_len = srd_root_str.size() / 2;
    memcpy(sigbuf, srd_root_u, srd_root_u_len);
    sigbuf += srd_root_u_len;
    free(srd_root_u);
    // File root
    uint8_t *file_root_u = hex_string_to_bytes(files_root_str.c_str(), files_root_str.size());
    size_t file_root_u_len = files_root_str.size() / 2;
    memcpy(sigbuf, file_root_u, file_root_u_len);
    sigbuf += file_root_u_len;
    free(file_root_u);
    // Added files
    memcpy(sigbuf, files_added.c_str(), files_added.size());
    sigbuf += files_added.size();
    // Deleted files 
    memcpy(sigbuf, files_deleted.c_str(), files_deleted.size());
    sigbuf += files_deleted.size();

    // Verify work report signature
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        crust_status = CRUST_SGX_SIGN_FAILED;
        goto cleanup;
    }
    wr_sig_u = hex_string_to_bytes(wr_sig.c_str(), wr_sig.size());
    if (wr_sig_u == NULL)
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
    memcpy(&sgx_wr_sig, wr_sig_u, sizeof(sgx_ec256_signature_t));
    free(wr_sig_u);
    sgx_status = sgx_ecdsa_verify(p_sigbuf, sigbuf_len, &sgx_pub_key, 
            &sgx_wr_sig, &p_result, ecc_state);
    if (SGX_SUCCESS != SGX_SUCCESS || p_result != SGX_EC_VALID)
    {
        log_err("Verify work report failed!Error code:%lx, result:%d\n", sgx_status, p_result);
        crust_status = CRUST_SGX_VERIFY_SIG_FAILED;
        goto cleanup;
    }
    sgx_ecc256_close_context(ecc_state);
    free(p_sigbuf);
    sigbuf = NULL;
    p_sigbuf = NULL;

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
    // MR enclave data
    mrenclave_str = upgrade_json[UPGRADE_MRENCLAVE].ToString();
    mrenclave_u = hex_string_to_bytes(mrenclave_str.c_str(), mrenclave_str.size());
    wl_sig = upgrade_json[UPGRADE_SIG].ToString();
    sigbuf_len = work_report.size() 
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_sha256_hash_t) 
        + sizeof(sgx_measurement_t);
    sigbuf = (uint8_t *)enc_malloc(sigbuf_len);
    if (sigbuf == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    memset(sigbuf, 0, sigbuf_len);
    p_sigbuf = sigbuf;
    // Work report
    memcpy(sigbuf, work_report.c_str(), work_report.size());
    sigbuf += work_report.size();
    // Srd root
    memcpy(sigbuf, wl_info[WL_SRD_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // Files root
    memcpy(sigbuf, wl_info[WL_FILE_ROOT_HASH].ToBytes(), sizeof(sgx_sha256_hash_t));
    sigbuf += sizeof(sgx_sha256_hash_t);
    // MR enclave
    memcpy(sigbuf, mrenclave_u, sizeof(sgx_measurement_t));
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
    sgx_status = sgx_ecdsa_verify(p_sigbuf, sigbuf_len, &sgx_pub_key, 
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

    // ----- Send old version's work report ----- //
    ocall_upload_workreport(&crust_status, wr_json.dump().c_str());
    if (CRUST_SUCCESS != crust_status)
    {
        log_err("Upload work report failed!\n");
        goto cleanup;
    }

    // If old version's mrenclave not equal to the new one
    if (memcpy(&current_mr_enclave, mrenclave_u, sizeof(sgx_measurement_t)) != 0)
    {
        // ----- Entry network ----- //
        ocall_entry_network(&crust_status);
        if (CRUST_SUCCESS != crust_status)
        {
            goto cleanup;
        }

        // ----- Send current version's work report ----- //
        wl->set_upgrade(sgx_pub_key);
        report_add_validated_proof();
        if (CRUST_SUCCESS != (crust_status = get_signed_work_report(block_hash_str.c_str(), std::atoi(block_height_str.c_str()))))
        {
            goto cleanup;
        }
        work_report = get_generated_work_report();
        ocall_upload_workreport(&crust_status, work_report.c_str());
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

    if (mrenclave_u != NULL)
    {
        free(mrenclave_u);
    }

    return crust_status;
}
