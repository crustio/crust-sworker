#include "App.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 1;

int run_as_server = 0;

/**
 * @description: application entry:
 *   use './app deamon' or './app' to start main progress
 *   use './app status' to get and printf validation status
 *   use './app report <block_hash>' to get and printf work report 
 * @param argc -> the number of command parameters
 * @param argv[] -> parameter array
 * @return: exit flag
 */
int SGX_CDECL main(int argc, char *argv[])
{
    if (argc == 1 || strcmp(argv[1], "daemon") == 0)
    {
        return main_daemon();
    }
    else if (strcmp(argv[1], "status") == 0)
    {
        return main_status();
    }
    else if (strcmp(argv[1], "server") == 0)
    {
        run_as_server = 1;
        return main_daemon();
    }
    else if (argc == 3 && strcmp(argv[1], "report") == 0)
    {
        return main_report(argv[2]);
    }
    else
    {
        printf("help txt\n");
    }

    return 0;
}

/**
 * @description: call sgx_create_enclave to initialize an enclave instance
 * @return: success or failure
 */
bool initialize_enclave(void)
{
	int sgx_support;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	/* Can we run SGX? */

    printf("[INFO] Initial enclave...\n");
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		printf("This system does not support Intel SGX.\n");
		return -1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			printf("Intel SGX is supported on this system but disabled in the BIOS\n");
			return -1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			printf("Intel SGX will be enabled after the next reboot\n");
			return -1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			printf("Intel SGX is supported on this sytem but not available for use\n");
			printf("The system may lock BIOS support, or the Platform Software is not available\n");
			return -1;
		}
	} 

	/* Launch the enclave */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("Init enclave failed.\n");
        return false;
    }

    /* Generate code measurement */

    if(SGX_SUCCESS != ecall_gen_sgx_measurement(global_eid, &ret))
    {
        printf("Generate code measurement failed!\n");
        return false;
    }

    /* Generate ecc key pair */
    if ( run_as_server )
    {
        if ( SGX_SUCCESS != ecall_gen_key_pair(global_eid, &ret) )
        {
            printf("Generate key pair failed!\n");
            return false;
        }
    }


    return true;
}

/**
 * @description: initialize the components:
 *   config -> user configurations and const configurations
 *   ipfs -> used to store meaningful files, please make sure IPFS is running before running daemon
 *   api handler -> external API interface 
 * @return: success or failure
 */
bool initialize_components(void)
{
    if (new_ipfs(get_config()->ipfs_api_base_url.c_str()) == NULL)
    {
        printf("Init ipfs failed.\n");
        return false;
    }

    /* API handler component */
    if (new_api_handler(get_config()->api_base_url.c_str(), &global_eid) == NULL)
    {
        printf("Init api handler failed.\n");
        return false;
    }

    return true;
}

/*
 * @description: entry network off-chain node sends quote to onchain node
 *   to verify identity
 * @return: success or failure
 * */
bool entry_network(void)
{
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_status_t status, sgxrv;
	//size_t pse_manifest_sz;
	//char *pse_manifest = NULL;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_quote_t *quote;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t sz= 0;
    uint32_t flags = get_config()->flags;
    sgx_quote_nonce_t nonce;
	char  *b64quote= NULL;
	char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *) malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char*)spid, get_config()->spid.c_str(), get_config()->spid.size());
    int i = 0;
    bool entry_status = true;

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

	/*if (OPT_ISSET(flags, OPT_PSE)) {
		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			printf("get_pse_manifest_size: %08x\n",
				status);
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			printf("get_pse_manifest: %08x\n",
				status);
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			printf("get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			return 1;
		}
	}*/

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		printf("[ERROR] sgx_init_quote: %08x\n", status);
		return false;
	}

	status= ecall_get_report(global_eid, &sgxrv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		printf("[ERROR] get_report: %08x\n", status);
		return false;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		printf("[ERROR] sgx_create_report: %08x\n", sgxrv);
		return false;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		printf("[ERROR] PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
		return false;
	}
	if ( status != SGX_SUCCESS ) {
		printf("[ERROR] SGX error while getting quote size: %08x\n", status);
		return false;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		printf("out of memory\n");
		return false;
	}

	memset(quote, 0, sz);
    printf("========== generate quote:\n");
    printf("========== linkable: %d\n", linkable);
    printf("========== spid    : %s\n", hexstring(spid,sizeof(sgx_spid_t)));
    printf("========== nonce   : %s\n", hexstring(&nonce,sizeof(sgx_quote_nonce_t)));
	status= sgx_get_quote(
        &report, 
        linkable, 
        spid,
        &nonce,
		NULL, 
        0,
        &qe_report,
		quote, 
        sz
    );
	if ( status != SGX_SUCCESS ) {
		printf("sgx_get_quote: %08x\n", status);
		return false;
	}

	/* Print our quote */
	printf("quote report_data: %s\n", hexstring((const void*)(quote->report_body.report_data.d),
            sizeof(quote->report_body.report_data.d)));
    printf("ias quote report version :%d\n",quote->version);
    printf("ias quote report signtype:%d\n",quote->sign_type);
    printf("ias quote report epid    :%d\n",*quote->epid_group_id);
    printf("ias quote report qe svn  :%d\n",quote->qe_svn);
    printf("ias quote report pce svn :%d\n",quote->pce_svn);
    printf("ias quote report xeid    :%d\n",quote->xeid);
    printf("ias quote report basename:%s\n",hexstring(quote->basename.name,32));
    printf("ias quote mr enclave     :%s\n",hexstring(&quote->report_body.mr_enclave,32));

    // Get base64 quote
	b64quote= base64_encode((char *) quote, sz);
	if ( b64quote == NULL ) {
		printf("Could not base64 encode quote\n");
		return false;
	}

    // TODO: PSE supported to avoid some attacks
	/*if (OPT_ISSET(flags, OPT_PSE)) {
		b64manifest= base64_encode((char *) pse_manifest, pse_manifest_sz);
		if ( b64manifest == NULL ) {
			free(b64quote);
			printf("Could not base64 encode manifest\n");
			return false;
		}
	}*/

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


    /* Send quote to validation node */

    printf("[INFO] Sending quote to on-chain node...\n");
    web::http::client::http_client_config cfg;
    cfg.set_timeout(std::chrono::seconds(IAS_TIMEOUT));
    web::http::client::http_client* self_api_client = new web::http::client::http_client(get_config()->api_base_url.c_str(), cfg);
    web::uri_builder builder(U("/entry/network"));
    web::http::http_response response;

    // Send quote to validation node, try out 3 times for network error.
    int net_tryout = IAS_TRYOUT;
    while(net_tryout >= 0) {
        try {
            response = self_api_client->request(web::http::methods::POST, builder.to_string(), b64quote).get();
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

    if ( response.status_code() != web::http::status_codes::OK ) 
    {
        printf("[ERROR] Entry network application failed!\n");
        entry_status = false;
        goto cleanup;
    }

    printf("[INFO] Entry network application successfully!\n");

cleanup:

    delete self_api_client;

    return entry_status;

}

/**
 * @description: run main progress
 * @return: exit flag
 */
int main_daemon()
{
    // New configure
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return -1;
    }
    get_config()->show();

    // Init enclave
    if (! initialize_enclave())
    {
        return -1;
    }

    // Entry network
    if ( ! run_as_server && ! entry_network() ) 
    {
        printf("\n[ERROR] Entry network failed!\n");
        return -1;
    }

    if (! initialize_components())
    {
        return -1;
    }


    /* Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores */
    #pragma omp parallel for
    for (size_t i = 0; i < get_config()->empty_capacity; i++)
    {
        ecall_plot_disk(global_eid, get_config()->empty_path.c_str());
    }

    ecall_generate_empty_root(global_eid);

    /* Main validate loop */
    ecall_main_loop(global_eid, get_config()->empty_path.c_str());

    /* End and release*/
    sgx_destroy_enclave(global_eid);
    delete get_config();
    delete get_ipfs();
    return 0;
}

/**
 * @description: run status command  to get and printf validation status
 * @return: exit flag
 */
int main_status(void)
{
    /* Get configurations */
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(get_config()->api_base_url.c_str());
    web::uri_builder builder(U("/status"));
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    printf("%s", response.extract_utf8string().get().c_str());
    delete self_api_client;
    return 0;
}

/**
 * @description: run report command to get and printf work report
 * @param block_hash -> use this hash to create report
 * @return: exit flag
 */
int main_report(const char *block_hash)
{
    /* Get configurations */
    if (new_config("Config.json") == NULL)
    {
        printf("Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(get_config()->api_base_url.c_str());
    web::uri_builder builder(U("/report"));
    builder.append_query("block_hash", block_hash);
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    printf("%s", response.extract_utf8string().get().c_str());
    delete self_api_client;
    return 0;
}
