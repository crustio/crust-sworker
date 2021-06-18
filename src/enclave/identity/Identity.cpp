#include "Identity.h"

using namespace std;

// Protect metadata 
sgx_thread_mutex_t g_metadata_mutex = SGX_THREAD_MUTEX_INITIALIZER;
// Upgrade generate metadata 
sgx_thread_mutex_t g_gen_work_report = SGX_THREAD_MUTEX_INITIALIZER;

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
    string certchain_1;
    size_t cstart, cend, count, i;
    vector<X509 *> certvec;
    size_t sigsz;
    crust_status_t status = CRUST_SUCCESS;
    size_t qbsz;
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_ec256_signature_t ecc_signature;

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, INTELSGXATTROOTCA);
    X509 *intelRootPemX509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    vector<string> response(IASReport, IASReport + size);

    Workload *wl = Workload::get_instance();


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

    std::string certchain = response[0];
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
    Defer def_certvec([&certvec, &count](void) {
        for (size_t i = 0; i < count; ++i)
        {
            X509_free(certvec[i]);
        }
    });

    X509 **certar = (X509 **)enc_malloc(sizeof(X509 *) * (count + 1));
    if (certar == NULL)
    {
        return CRUST_IAS_INTERNAL_ERROR;
    }
    Defer def_certar([&certar](void) {
        free(certar);
    });
    for (i = 0; i < count; ++i)
        certar[i] = certvec[i];
    certar[count] = NULL;

    // Create a STACK_OF(X509) stack from our certs

    STACK_OF(X509) *stack = cert_stack_build(certar);
    if (stack == NULL)
    {
        return CRUST_IAS_INTERNAL_ERROR;
    }
    Defer def_stack([&stack](void) {
        cert_stack_free(stack);
    });

    // Now verify the signing certificate

    int rv = cert_verify(cert_init_ca(intelRootPemX509), stack);

    if (!rv)
    {
        return CRUST_IAS_BAD_CERTIFICATE;
    }

    // The signing cert is valid, so extract and verify the signature

    std::string ias_sig = response[1];
    if (ias_sig == "")
    {
        return CRUST_IAS_BAD_SIGNATURE;
    }

    uint8_t *sig = (uint8_t *)base64_decode(ias_sig.c_str(), &sigsz);
    if (sig == NULL)
    {
        return CRUST_IAS_BAD_SIGNATURE;
    }
    Defer def_sig([&sig](void) {
        free(sig);
    });

    X509 *sign_cert = certvec[0]; /* The first cert in the list */

    /*
     * The report body is SHA256 signed with the private key of the
     * signing cert.  Extract the public key from the certificate and
     * verify the signature.
     */

    EVP_PKEY *pkey = X509_get_pubkey(sign_cert);
    if (pkey == NULL)
    {
        return CRUST_IAS_GETPUBKEY_FAILED;
    }
    Defer def_pkey([&pkey](void) {
        EVP_PKEY_free(pkey);
    });

    std::string isv_body = response[2];

    // verify IAS signature
    if (!sha256_verify((const uint8_t *)isv_body.c_str(), isv_body.length(), sig, sigsz, pkey))
    {
        return CRUST_IAS_BAD_SIGNATURE;
    }
    else
    {
        status = CRUST_SUCCESS;
    }

    // Verify quote
    int quoteSPos = (int)isv_body.find("\"" IAS_ISV_BODY_TAG "\":\"");
    quoteSPos = (int)isv_body.find("\":\"", quoteSPos) + 3;
    int quoteEPos = (int)isv_body.size() - 2;
    std::string ias_quote_body = isv_body.substr(quoteSPos, quoteEPos - quoteSPos);

    char *p_decode_quote_body = base64_decode(ias_quote_body.c_str(), &qbsz);
    if (p_decode_quote_body == NULL)
    {
        return CRUST_IAS_BAD_BODY;
    }
    Defer def_decode_quote_body([&p_decode_quote_body](void) {
        free(p_decode_quote_body);
    });

    sgx_quote_t *iasQuote = (sgx_quote_t *)enc_malloc(sizeof(sgx_quote_t));
    if (iasQuote == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    Defer def_iasQuote([&iasQuote](void) {
        free(iasQuote);
    });
    memset(iasQuote, 0, sizeof(sgx_quote_t));
    memcpy(iasQuote, p_decode_quote_body, qbsz);
    sgx_report_body_t *iasReportBody = &iasQuote->report_body;

    // This report data is our ecc public key
    // should be equal to the one contained in IAS report
    if (memcmp(iasReportBody->report_data.d, &wl->get_pub_key(), sizeof(sgx_ec256_public_t)) != 0)
    {
        return CRUST_IAS_REPORTDATA_NE;
    }

    // The mr_enclave should be equal to the one contained in IAS report
    if (memcmp(&iasReportBody->mr_enclave, &wl->get_mr_enclave(), sizeof(sgx_measurement_t)) != 0)
    {
        return CRUST_IAS_BADMEASUREMENT;
    }

    // ----- Sign IAS report with current private key ----- //
    sgx_status_t sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SIGN_PUBKEY_FAILED;
    }
    Defer def_ecc_state([&ecc_state](void) {
        sgx_ecc256_close_context(ecc_state);
    });

    // Generate identity data for sig
    size_t spos = certchain_1.find("-----BEGIN CERTIFICATE-----\n") + strlen("-----BEGIN CERTIFICATE-----\n");
    size_t epos = certchain_1.find("\n-----END CERTIFICATE-----");
    certchain_1 = certchain_1.substr(spos, epos - spos);
    replace(certchain_1, "\n", "");

    string chain_account_id = wl->get_account_id();
    uint8_t *p_account_id_u = hex_string_to_bytes(chain_account_id.c_str(), chain_account_id.size());
    if (p_account_id_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    Defer def_account_id_u([&p_account_id_u](void) {
        free(p_account_id_u);
    });
    size_t account_id_u_len = chain_account_id.size() / 2;

    std::vector<uint8_t> sig_buffer;
    vector_end_insert(sig_buffer, certchain_1);
    vector_end_insert(sig_buffer, ias_sig);
    vector_end_insert(sig_buffer, isv_body);
    vector_end_insert(sig_buffer, p_account_id_u, account_id_u_len);

    sgx_status = sgx_ecdsa_sign(sig_buffer.data(), sig_buffer.size(),
            const_cast<sgx_ec256_private_t *>(&wl->get_pri_key()), &ecc_signature, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SIGN_PUBKEY_FAILED;
    }
    
    // Get sworker identity and store it outside of sworker
    json::JSON id_json;
    id_json[IAS_CERT] = certchain_1;
    id_json[IAS_SIG] = ias_sig;
    id_json[IAS_ISV_BODY] = isv_body;
    id_json[IAS_CHAIN_ACCOUNT_ID] = chain_account_id;
    id_json[IAS_REPORT_SIG] = hexstring_safe(&ecc_signature, sizeof(sgx_ec256_signature_t));
    std::string id_str = id_json.dump();

    // Upload identity to chain
    ocall_upload_identity(&status, id_str.c_str());

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
    
    // ----- Store metadata ----- //
    std::vector<uint8_t> meta_buffer;
    // Append private data tag
    vector_end_insert(meta_buffer, reinterpret_cast<const uint8_t *>(SWORKER_PRIVATE_TAG), strlen(SWORKER_PRIVATE_TAG));
    meta_buffer.push_back('{');

    // Append srd
    std::string wl_title("\"" ID_SRD "\":[");
    vector_end_insert(meta_buffer, wl_title);
    for (size_t i = 0; i < wl->srd_hashs.size(); i++)
    {
        std::string srd_hex = "\"" + hexstring_safe(wl->srd_hashs[i], SRD_LENGTH) + "\"";
        if (CRUST_SUCCESS != (crust_status = vector_end_insert(meta_buffer, srd_hex)))
        {
            return CRUST_MALLOC_FAILED;
        }
        if (i != wl->srd_hashs.size() - 1)
        {
            meta_buffer.push_back(',');
        }
    }
    meta_buffer.push_back(']');
    meta_buffer.push_back(',');
    // Append id key pair
    vector_end_insert(meta_buffer, "\"" ID_KEY_PAIR "\":\"" + hex_id_key_str);
    // Append report height
    vector_end_insert(meta_buffer, "\",\"" ID_REPORT_HEIGHT "\":" + std::to_string(wl->get_report_height()));
    // Append chain account id
    vector_end_insert(meta_buffer, ",\"" ID_CHAIN_ACCOUNT_ID "\":\"" + wl->get_account_id());
    // Append previous public key
    if (wl->is_upgrade())
    {
        vector_end_insert(meta_buffer, "\",\"" ID_PRE_PUB_KEY "\":\"" + hexstring_safe(&wl->pre_pub_key, sizeof(wl->pre_pub_key)));
    }
    // Append files
    vector_end_insert(meta_buffer, std::string("\",\"" ID_FILE "\":["));
    for (size_t i = 0; i < sealed_files.size(); i++)
    {
        if (FILE_STATUS_PENDING == sealed_files[i][FILE_STATUS].get_char(CURRENT_STATUS))
        {
            json::JSON file;
            file[FILE_CID] = sealed_files[i][FILE_CID].ToString();
            file[FILE_STATUS] = sealed_files[i][FILE_STATUS].ToString();
            sealed_files[i] = file;
        }
        std::string file_str = sealed_files[i].dump();
        remove_char(file_str, '\n');
        remove_char(file_str, '\\');
        remove_char(file_str, ' ');
        if (CRUST_SUCCESS != (crust_status = vector_end_insert(meta_buffer, file_str)))
        {
            return crust_status;
        }
        if (i != sealed_files.size() - 1)
        {
            meta_buffer.push_back(',');
        }
    }
    meta_buffer.push_back(']');
    meta_buffer.push_back('}');

    crust_status = persist_set(ID_METADATA, meta_buffer.data(), meta_buffer.size());

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
    log_debug("Get metadata successfully!\n");
    meta_json = json::JSON::Load(p_data + strlen(SWORKER_PRIVATE_TAG), data_len);
    free(p_data);
    if (meta_json.size() == 0)
    {
        log_warn("Invalid metadata!\n");
        return CRUST_INVALID_META_DATA;
    }
    log_debug("Load metadata successfully!\n");
    // Verify meta data
    std::string id_key_pair_str = meta_json[ID_KEY_PAIR].ToString();
    uint8_t *p_id_key = hex_string_to_bytes(id_key_pair_str.c_str(), id_key_pair_str.size());
    if (p_id_key == NULL)
    {
        log_err("Identity: Get id key pair failed!\n");
        return CRUST_INVALID_META_DATA;
    }
    log_debug("Load id key pair successfully!\n");
    Defer def_id_key([&p_id_key](void) { free(p_id_key); });
    if (wl->try_get_key_pair() && memcmp(p_id_key, &wl->get_key_pair(), sizeof(ecc_key_pair)) != 0)
    {
        log_err("Identity: Get wrong id key pair!\n");
        return CRUST_INVALID_META_DATA;
    }
    log_debug("Verify metadata successfully!\n");

    // ----- Restore metadata ----- //
    Defer def_clean_all([&crust_status, &wl](void) { 
        if (CRUST_SUCCESS != crust_status)
        {
            wl->clean_all(); 
        }
    });
    // Restore srd
    if (CRUST_SUCCESS != (crust_status = wl->restore_srd(meta_json[ID_SRD])))
    {
        return crust_status;
    }
    log_debug("Restore srd successfully!\n");
    // Restore file
    if (CRUST_SUCCESS != (crust_status = wl->restore_file(meta_json[ID_FILE])))
    {
        return crust_status;
    }
    log_debug("Restore file successfully!\n");
    // Restore id key pair
    ecc_key_pair tmp_key_pair;
    memcpy(&tmp_key_pair, p_id_key, sizeof(ecc_key_pair));
    wl->set_key_pair(tmp_key_pair);
    log_debug("Restore id key pair successfully!\n");
    // Restore report height
    wl->set_report_height(meta_json[ID_REPORT_HEIGHT].ToInt());
    // Restore previous public key
    if (CRUST_SUCCESS != (crust_status = wl->restore_pre_pub_key(meta_json)))
    {
        return crust_status;
    }
    // Restore chain account id
    wl->set_account_id(meta_json[ID_CHAIN_ACCOUNT_ID].ToString());

    // Set restart flag
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
    SafeLock sl(g_gen_work_report);
    sl.lock();

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    Workload *wl = Workload::get_instance();

    // ----- Generate and upload work report ----- //
    // Current era has reported, wait for next slot
    if (block_height <= wl->get_report_height())
    {
        return CRUST_BLOCK_HEIGHT_EXPIRED;
    }
    if (block_height - wl->get_report_height() < REPORT_SLOT)
    {
        return CRUST_UPGRADE_WAIT_FOR_NEXT_ERA;
    }
    size_t report_height = wl->get_report_height();
    while (block_height - report_height > REPORT_SLOT)
    {
        report_height += REPORT_SLOT;
    }
    char report_hash[HASH_LENGTH * 2];
    if (report_hash == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(report_hash, 0, HASH_LENGTH * 2);
    ocall_get_block_hash(&crust_status, report_height, report_hash, HASH_LENGTH * 2);
    if (CRUST_SUCCESS != crust_status)
    {
        return CRUST_UPGRADE_GET_BLOCK_HASH_FAILED;
    }
    // Send work report
    // Wait a random time:[10, 50] block time
    size_t random_time = 0;
    sgx_read_rand(reinterpret_cast<uint8_t *>(&random_time), sizeof(size_t));
    random_time = ((random_time % (UPGRADE_WAIT_BLOCK_MAX - UPGRADE_WAIT_BLOCK_MIN + 1)) + UPGRADE_WAIT_BLOCK_MIN) * BLOCK_INTERVAL;
    log_info("Upgrade: Will generate and send work report after %ld blocks...\n", random_time / BLOCK_INTERVAL);
    if (CRUST_SUCCESS != (crust_status = gen_and_upload_work_report(report_hash, report_height, random_time, false, false)))
    {
        log_err("Fatal error! Send work report failed! Error code:%lx\n", crust_status);
        return CRUST_UPGRADE_GEN_WORKREPORT_FAILED;
    }
    log_debug("Upgrade: generate and send work report successfully!\n");

    // ----- Generate upgrade data ----- //
    // Clean pending status file
    wl->clean_pending_file();
    // Sign upgrade data
    std::string report_height_str = std::to_string(report_height);
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    Defer defer_ecc_state([&ecc_state](void) {
        if (ecc_state != NULL)
        {
            sgx_ecc256_close_context(ecc_state);
        }
    });
    uint8_t *p_srd_root = NULL;
    std::vector<uint8_t> srd_data = wl->serialize_srd(&crust_status, &p_srd_root);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    log_debug("Serialize srd data successfully!\n");
    uint8_t *p_file_root = NULL;
    std::vector<uint8_t> file_data = wl->serialize_file(&crust_status, &p_file_root);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }
    log_debug("Serialize file data successfully!\n");
    std::vector<uint8_t> sig_buffer;
    // Pub key
    const uint8_t *p_pub_key = reinterpret_cast<const uint8_t *>(&wl->get_pub_key());
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_pub_key, sizeof(sgx_ec256_public_t))))
    {
        return crust_status;
    }
    // Block height
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, report_height_str)))
    {
        return crust_status;
    }
    // Block hash
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, reinterpret_cast<uint8_t *>(report_hash), HASH_LENGTH * 2)))
    {
        return crust_status;
    }
    // Srd root
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_srd_root, HASH_LENGTH)))
    {
        return crust_status;
    }
    // Files root
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_file_root, HASH_LENGTH)))
    {
        return crust_status;
    }
    sgx_ec256_signature_t sgx_sig; 
    sgx_status = sgx_ecdsa_sign(sig_buffer.data(), sig_buffer.size(),
            const_cast<sgx_ec256_private_t *>(&wl->get_pri_key()), &sgx_sig, ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    log_debug("Generate upgrade signature successfully!\n");

    // ----- Get final upgrade data ----- //
    std::vector<uint8_t> upgrade_buffer;
    // Public key
    std::string pubkey_data = "{\"" UPGRADE_PUBLIC_KEY "\":\"" + hexstring_safe(&wl->get_pub_key(), sizeof(sgx_ec256_public_t)) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, pubkey_data)))
    {
        return crust_status;
    }
    // BLock height
    std::string block_height_data = ",\"" UPGRADE_BLOCK_HEIGHT "\":" + report_height_str;
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, block_height_data)))
    {
        return crust_status;
    }
    // Block hash
    std::string block_hash_data = std::string(",\"" UPGRADE_BLOCK_HASH "\":") + "\"" + std::string(report_hash, HASH_LENGTH * 2) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, block_hash_data)))
    {
        return crust_status;
    }
    // Srd
    std::string srd_title(",\"" UPGRADE_SRD "\":");
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, srd_title)))
    {
        return crust_status;
    }
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, srd_data.data(), srd_data.size())))
    {
        return crust_status;
    }
    // Files
    std::string files_title(",\"" UPGRADE_FILE "\":");
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, files_title)))
    {
        return crust_status;
    }
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, file_data.data(), file_data.size())))
    {
        return crust_status;
    }
    // Srd root
    std::string srd_root_data = ",\"" UPGRADE_SRD_ROOT "\":\"" + hexstring_safe(p_srd_root, HASH_LENGTH) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, srd_root_data)))
    {
        return crust_status;
    }
    // Files root
    std::string files_root_data = ",\"" UPGRADE_FILE_ROOT "\":\"" + hexstring_safe(p_file_root, HASH_LENGTH) + "\"";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, files_root_data)))
    {
        return crust_status;
    }
    // Signature
    std::string sig_data = ",\"" UPGRADE_SIG "\":\"" + hexstring_safe(&sgx_sig, sizeof(sgx_ec256_signature_t)) + "\"}";
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(upgrade_buffer, sig_data)))
    {
        return crust_status;
    }

    // Store upgrade data
    safe_ocall_store2(OCALL_STORE_UPGRADE_DATA, upgrade_buffer.data(), upgrade_buffer.size());
    log_debug("Store upgrade data successfully!\n");

    wl->set_upgrade_status(ENC_UPGRADE_STATUS_SUCCESS);

    return crust_status;
}

/**
 * @description: Restore workload from upgrade data
 * @param data -> Upgrade data per transfer
 * @param data_size -> Upgrade data size per transfer
 * @return: Restore status
 */
crust_status_t id_restore_from_upgrade(const uint8_t *data, size_t data_size)
{
    json::JSON upgrade_json = json::JSON::Load(data, data_size);

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    Workload *wl = Workload::get_instance();
    std::string report_height_str = upgrade_json[UPGRADE_BLOCK_HEIGHT].ToString();
    std::string report_hash_str = upgrade_json[UPGRADE_BLOCK_HASH].ToString();
    std::string a_pub_key_str = upgrade_json[UPGRADE_PUBLIC_KEY].ToString();
    uint8_t *a_pub_key_u = hex_string_to_bytes(a_pub_key_str.c_str(), a_pub_key_str.size());
    if (a_pub_key_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    sgx_ec256_public_t sgx_a_pub_key;
    memcpy(&sgx_a_pub_key, a_pub_key_u, sizeof(sgx_ec256_public_t));
    free(a_pub_key_u);

    // ----- Restore workload ----- //
    // Restore srd
    if (CRUST_SUCCESS != (crust_status = wl->restore_srd(upgrade_json[UPGRADE_SRD])))
    {
        log_err("Restore srd failed! Error code:%lx\n", crust_status);
        return CRUST_UPGRADE_RESTORE_SRD_FAILED;
    }
    log_debug("Restore srd data successfully!\n");
    // Restore file
    if (CRUST_SUCCESS != (crust_status = wl->restore_file(upgrade_json[UPGRADE_FILE])))
    {
        log_err("Restore file failed! Error code:%lx\n", crust_status);
        return CRUST_UPGRADE_RESTORE_FILE_FAILED;
    }
    log_debug("Restore file data successfully!\n");

    // ----- Verify workload signature ----- //
    json::JSON wl_info = wl->gen_workload_info();
    std::string wl_sig = upgrade_json[UPGRADE_SIG].ToString();
    std::vector<uint8_t> sig_buffer;
    // A's public key
    const uint8_t *p_a_pub_key = reinterpret_cast<const uint8_t *>(&sgx_a_pub_key);
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_a_pub_key, sizeof(sgx_ec256_public_t))))
    {
        return crust_status;
    }
    // Block height
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, report_height_str)))
    {
        return crust_status;
    }
    // Block hash
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, report_hash_str)))
    {
        return crust_status;
    }
    // Srd root
    const uint8_t *p_srd_root = wl_info[WL_SRD_ROOT_HASH].ToBytes();
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_srd_root, wl_info[WL_SRD_ROOT_HASH].size())))
    {
        return crust_status;
    }
    // Files root
    const uint8_t *p_file_root = wl_info[WL_FILE_ROOT_HASH].ToBytes();
    if (CRUST_SUCCESS != (crust_status = vector_end_insert(sig_buffer, p_file_root, wl_info[WL_FILE_ROOT_HASH].size())))
    {
        return crust_status;
    }
    // Verify signature
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != sgx_status)
    {
        return CRUST_SGX_SIGN_FAILED;
    }
    Defer defer([&ecc_state](void) {
        if (ecc_state != NULL)
        {
            sgx_ecc256_close_context(ecc_state);
        }
    });
    uint8_t *wl_sig_u = hex_string_to_bytes(wl_sig.c_str(), wl_sig.size());
    if (wl_sig_u == NULL)
    {
        return CRUST_UNEXPECTED_ERROR;
    }
    sgx_ec256_signature_t sgx_wl_sig;
    memcpy(&sgx_wl_sig, wl_sig_u, sizeof(sgx_ec256_signature_t));
    free(wl_sig_u);
    uint8_t p_result;
    sgx_status = sgx_ecdsa_verify(sig_buffer.data(), sig_buffer.size(), &sgx_a_pub_key, 
            &sgx_wl_sig, &p_result, ecc_state);
    if (SGX_SUCCESS != sgx_status || p_result != SGX_EC_VALID)
    {
        log_err("Verify workload failed!Error code:%lx, result:%d\n", sgx_status, p_result);
        return CRUST_SGX_VERIFY_SIG_FAILED;
    }

    // Verify workload srd and file root hash
    std::string upgrade_srd_root_str = upgrade_json[UPGRADE_SRD_ROOT].ToString();
    std::string upgrade_files_root_str = upgrade_json[UPGRADE_FILE_ROOT].ToString();
    if (wl_info[WL_SRD_ROOT_HASH].ToString().compare(upgrade_srd_root_str) != 0)
    {
        log_err("Verify workload srd root hash failed!\n");
        return CRUST_UPGRADE_BAD_SRD;
    }
    if (wl_info[WL_FILE_ROOT_HASH].ToString().compare(upgrade_files_root_str) != 0)
    {
        log_err("Verify workload file root hash failed!current hash:%s\n", wl_info[WL_FILE_ROOT_HASH].ToString().c_str());
        return CRUST_UPGRADE_BAD_FILE;
    }

    // ----- Entry network ----- //
    wl->set_upgrade(sgx_a_pub_key);
    ocall_entry_network(&crust_status);
    if (CRUST_SUCCESS != crust_status)
    {
        return crust_status;
    }

    // ----- Send current version's work report ----- //
    wl->report_add_validated_srd_proof();
    wl->report_add_validated_file_proof();
    if (CRUST_SUCCESS != (crust_status = gen_and_upload_work_report(report_hash_str.c_str(), std::atoi(report_height_str.c_str()), 0, true)))
    {
        return crust_status;
    }

    return crust_status;
}
