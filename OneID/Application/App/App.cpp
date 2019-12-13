#include "Enclave_u.h"
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#include "base64.h" 
#include "hexutil.h" 
#include "iasrequest.h" 
#include "sgx_detect.h"
#include "msgio.h"
#include "quote_size.h"
#include "common.h"
#include "json.hpp"

#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#define ENCLAVE_NAME "Enclave.signed.so"
#define OPT_ISSET(x,y)	x&y
#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

using namespace json;
using namespace std;

/* variable definition */
typedef struct ra_session_struct {
	unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
} ra_session_t;

static MsgIO *msgio = NULL;
static IAS_Connection *ias= NULL;


/* function definition */
int do_quote(sgx_enclave_id_t eid);

int do_verify(sgx_enclave_id_t eid);

int process_quote (sgx_enclave_id_t eid, MsgIO *msg, IAS_Connection *ias, sgx_quote_t *quote,
	ra_session_t *session);

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

const char *convert(string &s);

void uprintf(const char *str);

void uprintfHexString(const char *str);

void cleanup_and_exit(int signo);


/*
 * Main body: 
 * 1: initial IAS and MsgIO objects
 * 2: check and create sgx enclave
 * 3: do client or server action
 *    a: client does do_quote 
 *    b: server starts up a listen port and does do_verify
 * */

int main(int argc, char *argv[])
{
	int sgx_support;
	sgx_status_t status;
	sgx_launch_token_t token= { 0 };
	int updated= 0;
	sgx_enclave_id_t eid= 0;
	char flag_noproxy= 0;
	struct sigaction sact;
	int oops;
    const char *peer = NULL;

    string mode = "server";
    if(argc > 1) {
       if(strcmp(argv[1], "client") == 0) {
          mode = "client";
          peer = Settings::server.c_str();
       }
    }

    /* initial IAS request object */

    printf("[INFO] initial IAS request object\n");
	try {
		ias = new IAS_Connection(
			(Settings::QUERY_IAS_PRODUCTION) ? IAS_SERVER_PRODUCTION : IAS_SERVER_DEVELOPMENT,
			0,
			Settings::IAS_PRIMARY_SUBSCRIPTION_KEY,
			Settings::IAS_SECONDARY_SUBSCRIPTION_KEY
		);
	}
	catch (...) {
		oops = 1;
		printf("exception while creating IAS request object\n");
		return 1;
	}

	//if ( flag_noproxy ) ias->proxy_mode(IAS_PROXY_NONE);
	//else if (config.proxy_server != NULL) {
	//	ias->proxy_mode(IAS_PROXY_FORCE);
	//	ias->proxy(config.proxy_server, config.proxy_port);
	//}

    printf("[INFO] set ias agent\n");
	if ( Settings::USERAGENT != NULL ) {
		if ( ! ias->agent(Settings::USERAGENT) ) {
			printf("%s: unknown user agent\n", Settings::USERAGENT);
			return 0;
		}
	}

	/* 
	 * Install some rudimentary signal handlers. We just want to make 
	 * sure we gracefully shutdown the listen socket before we exit
	 * to avoid "address already in use" errors on startup.
	 */

    printf("[INFO] set http signal\n");
	sigemptyset(&sact.sa_mask);
	sact.sa_flags= 0;
	sact.sa_handler= &cleanup_and_exit;

	if ( sigaction(SIGHUP, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGINT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGTERM, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGQUIT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");


	/* Can we run SGX? */

    printf("[INFO] set sgx environment\n");
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		printf("This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			printf("Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			printf("Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			printf("Intel SGX is supported on this sytem but not available for use\n");
			printf("The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} 

	/* Launch the enclave */

	/* This funciton works for windows
    status = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG,
		&token, &updated, &eid, 0);
	if (status != SGX_SUCCESS) {
		printf("sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		return 1;
	}*/
	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		printf("sgx_create_enclave: %s: %08x\n", ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS )  {
			printf("Did you forget to set LD_LIBRARY_PATH?\n");
        }
		return 1;
	}

    /* create msgio instance */

    printf("[INFO] set msgio\n");
	try {
		msgio = new MsgIO(peer, Settings::port.c_str());
	} catch(...) {
		exit(1);
	}

    /* send quote to verification node */

    if(mode.compare("client") == 0) {
        do_quote(eid);
    } else if(mode.compare("server") != 0) {
        printf("[ERROR] Please input right mode!");
        exit(1);
    }

    /* Start listen port to recieve application */

    do_verify(eid);
}

/*
 * offchain node sends quote to onchain node
 * to verify identity
 * */

int do_quote(sgx_enclave_id_t eid)
{
    printf("[INFO] request node sends quote to verify node...\n");
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_status_t status, sgxrv;
	size_t pse_manifest_sz;
	char *pse_manifest = NULL;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_quote_t *quote;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t sz= 0;
    uint32_t flags = Settings::flags;
    sgx_quote_nonce_t nonce;
	char  *b64quote= NULL;
	char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *) malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char*)spid, Settings::SPID.c_str(), Settings::SPID.size());
    int i = 0;
    Msg_ret *msg_ret;

    /* get nonce */

	for(i= 0; i< 2; ++i) {
		int retry= 10;
		unsigned char ok= 0;
		uint64_t *np= (uint64_t *) &nonce;
		while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
		if ( ok == 0 ) {
			fprintf(stderr, "nonce: RDRAND underflow\n");
			exit(1);
		}
	}


 	if (OPT_ISSET(flags, OPT_LINK)) linkable= SGX_LINKABLE_SIGNATURE;


	/* Platform services info */
	if (OPT_ISSET(flags, OPT_PSE)) {
		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			printf("get_pse_manifest_size: %08x\n",
				status);
            delete msgio;
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			printf("get_pse_manifest: %08x\n",
				status);
            delete msgio;
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			printf("get_sec_prop_desc_ex: %08x\n",
				sgxrv);
            delete msgio;
			return 1;
		}
	}

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		printf("sgx_init_quote: %08x\n", status);
        delete msgio;
		return 1;
	}

	status= get_report(eid, &sgxrv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		printf("get_report: %08x\n", status);
        delete msgio;
		return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		printf("sgx_create_report: %08x\n", sgxrv);
        delete msgio;
		return 1;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		printf("PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        delete msgio;
		return 1;
	}
	if ( status != SGX_SUCCESS ) {
		printf("SGX error while getting quote size: %08x\n", status);
        delete msgio;
		return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		printf("out of memory\n");
        delete msgio;
		return 1;
	}

	memset(quote, 0, sz);
    printf("========== generate quote:\n");
    printf("========== linkable: %d\n", linkable);
    printf("========== spid    : %s\n", hexstring(spid,sizeof(sgx_spid_t)));
    printf("========== nonce   : %s\n", hexstring(&nonce,sizeof(sgx_quote_nonce_t)));
	status= sgx_get_quote(&report, linkable, spid,
		//(OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
        &nonce,
		NULL, 0,
		//(OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL, 
        &qe_report,
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		printf("sgx_get_quote: %08x\n", status);
        delete msgio;
		return 1;
	}

	/* Print our quote */
	printf("quote report_data: %s\n", hexstring((const void*)(quote->report_body.report_data.d),
            sizeof(quote->report_body.report_data.d)));
    printf("ias quote report version :%d\n",quote->version);
    printf("ias quote report signtype:%d\n",quote->sign_type);
    printf("ias quote report epid    :%d\n",quote->epid_group_id);
    printf("ias quote report qe svn  :%d\n",quote->qe_svn);
    printf("ias quote report pce svn :%d\n",quote->pce_svn);
    printf("ias quote report xeid    :%d\n",quote->xeid);
    printf("ias quote report basename:%s\n",hexstring(quote->basename.name,32));
    printf("ias quote mr enclave     :%s\n",hexstring(&quote->report_body.mr_enclave,32));

    // get base64 quote
	b64quote= base64_encode((char *) quote, sz);
	if ( b64quote == NULL ) {
		printf("Could not base64 encode quote\n");
        delete msgio;
		return 1;
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		b64manifest= base64_encode((char *) pse_manifest, pse_manifest_sz);
		if ( b64manifest == NULL ) {
			free(b64quote);
			printf("Could not base64 encode manifest\n");
            delete msgio;
			return 1;
		}
	}

	printf("{\n");
	printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
	if ( OPT_ISSET(flags, OPT_NONCE) ) {
		printf(",\n\"nonce\":\"");
		print_hexstring(stdout, &nonce, 16);
		printf("\"");
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		printf(",\n\"pseManifest\":\"%s\"", b64manifest);	
	}
	printf("\n}\n");


    /* send quote to validation node */

    msgio->send(quote, sz);

    msgio->read((void **)&msg_ret, NULL);
    if(IAS_VERIFY_SUCCESS == msg_ret->statusCode) {
        printf("On chain verification successfully! Message info: %s\n", msg_ret->msg);
    } else {
        printf("On chain verification failed! Error info: %s\n", msg_ret->msg);
    }

}

/*
 * On-chain node waits for entrance chain application
 * */

int do_verify(sgx_enclave_id_t eid)
{
    printf("[INFO] verify node verifies quote...\n");
	while ( msgio->server_loop() ) {
		ra_session_t session;
        sgx_quote_t quote;
        Msg_ret msg_ret;

        msg_ret.statusCode = IAS_VERIFY_SUCCESS;
        memset(msg_ret.msg, 0, MSGRETSIZE);
        memcpy(msg_ret.msg, "Verify IAS report successfully!", MSGRETSIZE);

		memset(&session, 0, sizeof(ra_session_t));

        /* Read quote from comming node */
        if( ! process_quote(eid, msgio, ias, &quote, &session) ) {
            msg_ret.statusCode = IAS_VERIFY_FAILED;
            memcpy(msg_ret.msg, "error processing quote and IAS report", MSGRETSIZE);
			printf("%s\n", msg_ret.msg);
        }	

        msgio->send(&msg_ret, sizeof(Msg_ret));
    }


	msgio->disconnect();
    
    return 0;
}

/*
 * Recieve offchain node quote and sends it to IAS 
 * get report returned by IAS and verify it on enclave
 * */

int process_quote (sgx_enclave_id_t eid, MsgIO *msg, IAS_Connection *ias, sgx_quote_t *quote,
	ra_session_t *session)
{
    int rv;
    size_t sz = 1116;
    ias_status_t ias_status_ret;
    sgx_status_t sgx_status_ret;
    //sgx_quote_t *quote_r;
    rv = msgio->read((void **) &quote, NULL);
	if ( rv == -1 ) {
		printf("system error reading quote\n");
		return 0;
	} else if ( rv == 0 ) {
		printf("protocol error reading quote\n");
		return 0;
	}

    /* Store off-chain quote in enclave */

    sgx_status_t store_quote_ret = enclave_store_quote(eid, &sgx_status_ret, (const char*)quote, sz);
    if ( store_quote_ret != SGX_SUCCESS ) {
        fprintf(stderr, "Store off-chain quote failed!");
        return 0;
    }

	fprintf(stderr, "quote size: %d, quote report_data: %s\n", sz, hexstring((const void*)(quote->report_body.report_data.d),
            sizeof(quote->report_body.report_data.d)));

	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;
    int version = IAS_API_DEF_VERSION;
    vector<string> response_v;

	try {
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		printf("Exception while creating IAS request object\n");
		if ( req != NULL ) delete req;
		return 0;
	}

	char * b64quote= base64_encode((char *) quote, sz);

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
	
	status= req->report(payload, content, messages, &response_v);
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

		if ( Settings::verbose ) {
			edividerWithText("Report Body");
			printf("%s\n", content.c_str());
			edivider();
			if ( messages.size() ) {
				edividerWithText("IAS Advisories");
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					printf("%s\n", i->c_str());
				}
				edivider();
			}
		}

		if ( Settings::verbose ) {
			edividerWithText("IAS Report - JSON - Required Fields");
			if ( version >= 3 ) {
				printf("version               = %d\n",
					reportObj["version"].ToInt());
			}
			printf("id:                   = %s\n",
				reportObj["id"].ToString().c_str());
			printf("timestamp             = %s\n",
				reportObj["timestamp"].ToString().c_str());
			printf("isvEnclaveQuoteStatus = %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			printf("isvEnclaveQuoteBody   = %s\n",
				reportObj["isvEnclaveQuoteBody"].ToString().c_str());
            string iasQuoteStr = reportObj["isvEnclaveQuoteBody"].ToString();
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

			edividerWithText("IAS Report - JSON - Optional Fields");

			printf("platformInfoBlob  = %s\n",
				reportObj["platformInfoBlob"].ToString().c_str());
			printf("revocationReason  = %s\n",
				reportObj["revocationReason"].ToString().c_str());
			printf("pseManifestStatus = %s\n",
				reportObj["pseManifestStatus"].ToString().c_str());
			printf("pseManifestHash   = %s\n",
				reportObj["pseManifestHash"].ToString().c_str());
			printf("nonce             = %s\n",
				reportObj["nonce"].ToString().c_str());
			printf("epidPseudonym     = %s\n",
				reportObj["epidPseudonym"].ToString().c_str());
			edivider();
		}

        /*
         * If the report returned a version number (API v3 and above), make
         * sure it matches the API version we used to fetch the report.
    	 *
    	 * For API v3 and up, this field MUST be in the report.
         */
    
    	if ( reportObj.hasKey("version") ) {
    		unsigned int rversion= (unsigned int) reportObj["version"].ToInt();
    		if ( Settings::verbose )
    			printf("+++ Verifying report version against API version\n");
    		if ( version != rversion ) {
    			printf("Report version %u does not match API version %u\n",
    				rversion , version);
    			delete req;
    			return 0;
    		}
    	} else if ( version >= 3 ) {
    		printf("attestation report version required for API version >= 3\n");
    		delete req;
    		return 0;
    	}

    } else {

	    printf("attestation query returned %lu: \n", status);
    
	    switch(status) {
	    	case IAS_QUERY_FAILED:
	    		printf("Could not query IAS\n");
	    		break;
	    	case IAS_BADREQUEST:
	    		printf("Invalid payload\n");
	    		break;
	    	case IAS_UNAUTHORIZED:
	    		printf("Failed to authenticate or authorize request\n");
	    		break;
	    	case IAS_SERVER_ERR:
	    		printf("An internal error occurred on the IAS server\n");
	    		break;
	    	case IAS_UNAVAILABLE:
	    		printf("Service is currently not able to process the request. Try again later.\n");
	    		break;
	    	case IAS_INTERNAL_ERROR:
	    		printf("An internal error occurred while processing the IAS response\n");
	    		break;
	    	case IAS_BAD_CERTIFICATE:
	    		printf("The signing certificate could not be validated\n");
	    		break;
	    	case IAS_BAD_SIGNATURE:
	    		printf("The report signature could not be validated\n");
	    		break;
	    	default:
	    		if ( status >= 100 && status < 600 ) {
	    			printf("Unexpected HTTP response code\n");
	    		} else {
				printf("An unknown error occurred.\n");
			}
	    }

    }

    /* Verify IAS report in enclave */

    vector<const char *> vc;
    transform(response_v.begin(), response_v.end(), back_inserter(vc), convert);
    
    vector<string> teststr(vc.data(), vc.data() + vc.size());

    printf("==================== print response data:\n");
    for(auto it = teststr.begin(); it != teststr.end(); it++) {
        printf("-------------------value:%s\n", it->c_str());
    }

    if(vc.size() != 6) {
        fprintf(stderr, "Get IAS response failed!\n");
        delete req;
        return 1;
    }

    printf("========================= call enclave =======================\n");
    
    sgx_status_t report_ret = enclave_verify_iasReport(eid, &ias_status_ret, vc.data(), vc.size());
    if(SGX_SUCCESS == report_ret) {
        switch(ias_status_ret) {
            case IAS_VERIFY_SUCCESS:
                printf("Verify IAS report succeefully!\n");
                break;
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
        if(ias_status_ret == IAS_VERIFY_SUCCESS) {

            // Send a verification request to chain
        
        }
    } else {
	    fprintf(stderr, "Invoke verify ias report failed!\n");
    }


	delete req;

	return 1;
}


/* 
 * Used to search and create enclave on Linux 
 * */

sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) {
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
    }

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 ) {
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
    }

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) ) {
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
    }
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) ) {
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
    }

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) ) {
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
    }

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}

const char *convert(string &s)
{
    return s.c_str();
}

void uprintf(const char *str)
{
    printf("========== from enclave:%s\n", str);
    fflush(stdout);
}

void uprintfHexString(const char *str)
{
    printf("========== from enclave:%s\n", hexstring(str, 64));
    fflush(stdout);
}

void cleanup_and_exit(int signo)
{
	/* Signal-safe, and we don't care if it fails or is a partial write. */

	ssize_t bytes= write(STDERR_FILENO, "\nterminating\n", 13);

	/*
	 * This destructor consists of signal-safe system calls (close,
	 * shutdown).
	 */

	delete msgio;

	exit(1);
}
