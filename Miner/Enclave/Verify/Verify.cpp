/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#include "Verify.h"

using namespace std;

extern unsigned char offChain_report_data[];

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

string url_decode(string str)
{
	string decoded;
	size_t i;
	size_t len= str.length();

	for (i= 0; i< len; ++i) {
		if ( str[i] == '+' ) decoded+= ' ';
		else if ( str[i] == '%' ) {
			char *e= NULL;
			unsigned long int v;

			// Have a % but run out of characters in the string

			if ( i+3 > len ) throw length_error("premature end of string");

			v= strtoul(str.substr(i+1, 2).c_str(), &e, 16);

			// Have %hh but hh is not a valid hex code.
			if ( *e ) throw out_of_range("invalid encoding");

			decoded+= static_cast<char>(v);
			i+= 2;
		} else decoded+= str[i];
	}

	return decoded;
}

int cert_load_size (X509 **cert, const char *pemdata, size_t sz)
{
	BIO * bmem;
	error_type= e_none;

	bmem= BIO_new(BIO_s_mem());
	if ( bmem == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( BIO_write(bmem, pemdata, (int) sz) != (int) sz ) {
		error_type= e_crypto;
		goto cleanup;
	}

	*cert= PEM_read_bio_X509(bmem, NULL, NULL, NULL);
	if ( *cert == NULL ) error_type= e_crypto;

cleanup:
	if ( bmem != NULL ) BIO_free(bmem);

	return (error_type == e_none);
}

int cert_load (X509 **cert, const char *pemdata)
{
	return cert_load_size(cert, pemdata, strlen(pemdata));
}

/*
 * Take an array of certificate pointers and build a stack.
 */

STACK_OF(X509) * cert_stack_build (X509 **certs)
{
	X509 **pcert;
	STACK_OF(X509) *stack;

	error_type= e_none;

	stack= sk_X509_new_null();
	if ( stack == NULL ) {
		error_type= e_crypto;
		return NULL;
	}

	for ( pcert= certs; *pcert!= NULL; ++pcert ) sk_X509_push(stack, *pcert);

	return stack;
}

/*
 * Verify cert chain against our CA in store. Assume the first cert in
 * the chain is the one to validate. Note that a store context can only
 * be used for a single verification so we need to do this every time
 * we want to validate a cert.
 */

int cert_verify (X509_STORE *store, STACK_OF(X509) *chain)
{
	X509_STORE_CTX *ctx;
	X509 *cert= sk_X509_value(chain, 0);

	error_type= e_none;

	ctx= X509_STORE_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		return 0;
	}

	if ( X509_STORE_CTX_init(ctx, store, cert, chain) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( X509_verify_cert(ctx) != 1 ) error_type=e_crypto;

cleanup:
	if ( ctx != NULL ) X509_STORE_CTX_free(ctx);

	return (error_type == e_none);
}

void cert_stack_free (STACK_OF(X509) *chain)
{
	sk_X509_free(chain);
}

/*==========================================================================
 * HMAC
 *========================================================================== */

int sha256_verify(const unsigned char *msg, size_t mlen, unsigned char *sig,
    size_t sigsz, EVP_PKEY *pkey, int *result)
{
	EVP_MD_CTX *ctx;

	error_type= e_none;

	ctx= EVP_MD_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestVerifyUpdate(ctx, msg, mlen) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestVerifyFinal(ctx, sig, sigsz) != 1 ) error_type= e_crypto;

cleanup:
	if ( ctx != NULL ) EVP_MD_CTX_free(ctx);
	return (error_type == e_none);
}

X509_STORE * cert_init_ca(X509 *cert)
{
	X509_STORE *store;

	error_type= e_none;

	store= X509_STORE_new();
	if ( store == NULL ) {
		error_type= e_crypto;
		return NULL;
	}

	if ( X509_STORE_add_cert(store, cert) != 1 ) {
		X509_STORE_free(store);
		error_type= e_crypto;
		return NULL;
	}

	return store;
}

char *base64_decode(const char *msg, size_t *sz)
{
	BIO *b64, *bmem;
	char *buf;
	size_t len= strlen(msg);

	buf= (char *) malloc(len+1);
	if ( buf == NULL ) return NULL;
	memset(buf, 0, len+1);

	b64= BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem= BIO_new_mem_buf(msg, (int) len);

	BIO_push(b64, bmem);

	*sz= BIO_read(b64, buf, (int) len);
	if ( *sz == -1 ) {
		free(buf);
		return NULL;
	}

	BIO_free_all(bmem);

	return buf;
}

ias_status_t ecall_verify_iasreport_real(const char ** IASReport, int len)
{
    string certchain;
    size_t cstart, cend, count, i;
    X509 **certar;
    STACK_OF(X509) *stack;
    vector<X509 *> certvec;
    vector<string> messages;
    int rv;
    string sigstr, header;
    size_t sigsz;
    X509 *sign_cert;
    EVP_PKEY *pkey= NULL;
    ias_status_t status = IAS_VERIFY_SUCCESS;
    unsigned char *sig= NULL;
    string content;
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, INTELSGXATTROOTCA);
    X509 * intelRootPemX509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    vector<string> response(IASReport, IASReport + len);
    int quoteSPos = 0;
    int quoteEPos = 0;
    string iasQuoteBodyStr;
    sgx_quote_t *iasQuote;
    sgx_report_body_t *iasReportBody;
    char *p_decode_quote_body = NULL;
    char *p_decode_ = NULL;
    size_t qbsz;
    sgx_report_t verify_report;
    sgx_target_info_t verify_target_info;
    sgx_report_data_t verify_report_data;
    sgx_status_t sgx_status;

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

	certchain= response[0];
	if ( certchain == "" ) {
        return IAS_BAD_CERTIFICATE;
	}

	// URL decode
	try {
		certchain= url_decode(certchain);
	}
	catch (...) {
		return IAS_BAD_CERTIFICATE;
	}

	// Build the cert stack. Find the positions in the string where we
	// have a BEGIN block.

	cstart= cend= 0;
	while (cend != string::npos ) {
		X509 *cert;
		size_t len;

		cend= certchain.find("-----BEGIN", cstart+1);
		len= ( (cend == string::npos) ? certchain.length() : cend )-cstart;

		if ( ! cert_load(&cert, certchain.substr(cstart, len).c_str()) ) {
			return IAS_BAD_CERTIFICATE;
		}

		certvec.push_back(cert);
		cstart= cend;
	}

	count= certvec.size();

	certar= (X509**) malloc(sizeof(X509 *)*(count+1));
	if ( certar == 0 ) {
		return IAS_INTERNAL_ERROR;
	}
	for (i= 0; i< count; ++i) certar[i]= certvec[i];
	certar[count]= NULL;

	// Create a STACK_OF(X509) stack from our certs

	stack= cert_stack_build(certar);
	if ( stack == NULL ) {
		status= IAS_INTERNAL_ERROR;
		goto cleanup;
	}

	// Now verify the signing certificate

	rv= cert_verify(cert_init_ca(intelRootPemX509), stack);

	if ( ! rv ) {
		status= IAS_BAD_CERTIFICATE;
		goto cleanup;
	}

	// The signing cert is valid, so extract and verify the signature

	sigstr= response[1];
	if ( sigstr == "" ) {
		status= IAS_BAD_SIGNATURE;
		goto cleanup;
	}

	sig= (unsigned char *) base64_decode(sigstr.c_str(), &sigsz);
	if ( sig == NULL ) {
		status= IAS_BAD_SIGNATURE;
		goto cleanup;
	}

	sign_cert= certvec[0]; /* The first cert in the list */

	/*
	 * The report body is SHA256 signed with the private key of the
	 * signing cert.  Extract the public key from the certificate and
	 * verify the signature.
	 */

	pkey= X509_get_pubkey(sign_cert);
	if ( pkey == NULL ) {
		status= IAS_GETPUBKEY_FAILED;
		goto cleanup;
	}

	content= response[2];

    // verify IAS signature

	if ( ! sha256_verify((const unsigned char *) content.c_str(),
		content.length(), sig, sigsz, pkey, &rv) ) {

        // do sha256_verify failed
		status= IAS_BAD_SIGNATURE;
        goto cleanup;
	} else {
		if ( rv ) {
			status= IAS_VERIFY_SUCCESS;
		} else {
			status= IAS_BAD_SIGNATURE;
            goto cleanup;
		}
	}


    /* Verify quote */
    
    quoteSPos = content.find("\"isvEnclaveQuoteBody\":\"");
    quoteSPos = content.find("\":\"",quoteSPos) + 3;
    quoteEPos = content.size() - 2;
    iasQuoteBodyStr = content.substr(quoteSPos, quoteEPos - quoteSPos);

    iasQuote = (sgx_quote_t*)malloc(sizeof(sgx_quote_t));
    memset(iasQuote, 0, sizeof(sgx_quote_t));
    p_decode_quote_body = base64_decode(iasQuoteBodyStr.c_str(), &qbsz);
    memcpy(iasQuote, p_decode_quote_body, qbsz);
    iasReportBody = &iasQuote->report_body;

    //eprintfhexstring("report_data    : %s\n", &iasReportBody->report_data);
    //eprintfhexstring("report_data org: %s\n", offChain_report_data);

    // This report data is our ecc public key
    // should be equal to the one contained in IAS report
    if( memcmp(iasReportBody->report_data.d, offChain_report_data, REPORT_DATA_SIZE) != 0 ) {
        status = IAS_REPORTDATA_NE;
        goto cleanup;
    } else {
        status = IAS_VERIFY_SUCCESS;
    }

    // Get report from current enclave
    memset(&verify_report, 0, sizeof(sgx_report_t));
    memset(&verify_report_data, 0, sizeof(sgx_report_data_t));
    memset(&verify_target_info, 0, sizeof(sgx_target_info_t));
    sgx_status = sgx_create_report(&verify_target_info, &verify_report_data, &verify_report);
    if(SGX_SUCCESS != sgx_status) {
        status = IAS_GET_REPORT_FAILED;
    } else {
        //eprintfhexstring("%s", &verify_report.body.mr_enclave);
        // The mr_enclave should be equal to the one contained in IAS report
        if ( memcmp(&iasReportBody->mr_enclave, &verify_report.body.mr_enclave, 
            sizeof(sgx_measurement_t)) != 0 ) {
            status = IAS_BADMEASUREMENT;
        } else {
            status = IAS_VERIFY_SUCCESS;
        }
    }


cleanup:
	if ( pkey != NULL ) EVP_PKEY_free(pkey);
	cert_stack_free(stack);
	free(certar);
	for (i= 0; i<count; ++i) X509_free(certvec[i]);
	free(sig);
    free(iasQuote);

	return status;
}
