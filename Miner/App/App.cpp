#include "App.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
int run_as_server = 0;
std::vector<sgx_enclave_id_t> enclaveIDs;
pid_t workerPID=-1, monitorPID=-1;
int pipe_fd[2];
int session_type;
bool isChild = false;

extern ApiHandler *api_handler;
extern FILE *felog;
extern Ipfs *ipfs;

void start_monitor(void);
void start_worker(void);
void *do_disk_related(void *arg);

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

bool initialize_config(void)
{
    bool status = true;
    // New configure
    if (new_config("Config.json") == NULL)
    {
        cfprintf(felog, CF_ERROR "Init config failed.\n");
        return false;
    }
    get_config()->show();

    // Create log file
    if(felog == NULL)
    {
        felog = create_logfile("./logs/entry.log");
    }

    return status;
}

/**
 * @description: call sgx_create_enclave to initialize an enclave instance
 * @return: success or failure
 */
bool initialize_enclave()
{
    int sgx_support;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Can we run SGX? */
    cfprintf(felog, CF_INFO "Initial enclave...\n");
    sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO)
    {
        cfprintf(felog, CF_ERROR "This system does not support Intel SGX.\n");
        return -1;
    }
    else
    {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
        {
            cfprintf(felog, CF_ERROR "Intel SGX is supported on this system but disabled in the BIOS\n");
            return -1;
        }
        else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
        {
            cfprintf(felog, CF_ERROR "Intel SGX will be enabled after the next reboot\n");
            return -1;
        }
        else if (!(sgx_support & SGX_SUPPORT_ENABLED))
        {
            cfprintf(felog, CF_ERROR "Intel SGX is supported on this sytem but not available for use. \
                    The system may lock BIOS support, or the Platform Software is not available\n");
            return -1;
        }
    }

    /* Launch the enclave */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "Init enclave failed.Error code:%08x\n", ret);
        return false;
    }

    /* Generate code measurement */
    if (SGX_SUCCESS != ecall_gen_sgx_measurement(global_eid, &ret))
    {
        cfprintf(felog, CF_ERROR "Generate code measurement failed!error code:%08x\n", ret);
        return false;
    }

    /* Generate ecc key pair */
    if (run_as_server)
    {
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &ret))
        {
            cfprintf(felog, CF_ERROR "Generate key pair failed!\n");
            return false;
        }
    }
    cfprintf(felog, CF_INFO "Initial enclave successfully!\n");

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
        cfprintf(felog, CF_ERROR "Init ipfs failed.\n");
        return false;
    }

    /* API handler component */
    if (new_api_handler(get_config()->api_base_url.c_str(), &global_eid) == NULL)
    {
        cfprintf(felog, CF_ERROR "Init api handler failed.\n");
        return false;
    }

    if(api_handler->start() == -1)
    {
        cfprintf(felog, CF_ERROR "Start network service failed!\n");
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
    sgx_quote_sign_type_t linkable = SGX_UNLINKABLE_SIGNATURE;
    sgx_status_t status, sgxrv;
    //size_t pse_manifest_sz;
    //char *pse_manifest = NULL;
    sgx_report_t report;
    sgx_report_t qe_report;
    sgx_quote_t *quote;
    sgx_target_info_t target_info;
    sgx_epid_group_id_t epid_gid;
    uint32_t sz = 0;
    uint32_t flags = get_config()->flags;
    sgx_quote_nonce_t nonce;
    char *b64quote = NULL;
    char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *)malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char *)spid, get_config()->spid.c_str(), get_config()->spid.size());
    int i = 0;
    bool entry_status = true;


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
            fprintf(stderr, "nonce: RDRAND underflow\n");
            exit(1);
        }
    }

    if (OPT_ISSET(flags, OPT_LINK))
        linkable = SGX_LINKABLE_SIGNATURE;

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

    status = sgx_init_quote(&target_info, &epid_gid);
    if (status != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "sgx_init_quote: %08x\n", status);
        return false;
    }

    status = ecall_get_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "get_report: %08x\n", status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "sgx_create_report: %08x\n", sgxrv);
        return false;
    }

    // sgx_get_quote_size() has been deprecated, but our PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        cfprintf(felog, CF_ERROR "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return false;
    }
    if (status != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "SGX error while getting quote size: %08x\n", status);
        return false;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        cfprintf(felog, CF_ERROR "out of memory\n");
        return false;
    }

    memset(quote, 0, sz);
    fprintf(felog, "========== linkable: %d\n", linkable);
    fprintf(felog, "========== spid    : %s\n", hexstring(spid, sizeof(sgx_spid_t)));
    fprintf(felog, "========== nonce   : %s\n", hexstring(&nonce, sizeof(sgx_quote_nonce_t)));
    status = sgx_get_quote(
        &report,
        linkable,
        spid,
        &nonce,
        NULL,
        0,
        &qe_report,
        quote,
        sz);
    if (status != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "sgx_get_quote: %08x\n", status);
        return false;
    }

    /* Print our quote */
    fprintf(felog, "quote report_data: %s\n", hexstring((const void *)(quote->report_body.report_data.d), sizeof(quote->report_body.report_data.d)));
    fprintf(felog, "ias quote report version :%d\n", quote->version);
    fprintf(felog, "ias quote report signtype:%d\n", quote->sign_type);
    fprintf(felog, "ias quote report epid    :%d\n", *quote->epid_group_id);
    fprintf(felog, "ias quote report qe svn  :%d\n", quote->qe_svn);
    fprintf(felog, "ias quote report pce svn :%d\n", quote->pce_svn);
    fprintf(felog, "ias quote report xeid    :%d\n", quote->xeid);
    fprintf(felog, "ias quote report basename:%s\n", hexstring(quote->basename.name, 32));
    fprintf(felog, "ias quote mr enclave     :%s\n", hexstring(&quote->report_body.mr_enclave, 32));

    // Get base64 quote
    b64quote = base64_encode((char *)quote, sz);
    if (b64quote == NULL)
    {
        cfprintf(felog, CF_ERROR "Could not base64 encode quote\n");
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

    fprintf(felog, "{\n");
    fprintf(felog, "\"isvEnclaveQuote\":\"%s\"", b64quote);
    if (OPT_ISSET(flags, OPT_NONCE))
    {
        fprintf(felog, ",\n\"nonce\":\"");
        print_hexstring(stdout, &nonce, 16);
        fprintf(felog, "\"");
    }

    if (OPT_ISSET(flags, OPT_PSE))
    {
        fprintf(felog, ",\n\"pseManifest\":\"%s\"", b64manifest);
    }
    fprintf(felog, "\n}\n");

    /* Send quote to validation node */
    cfprintf(felog, CF_INFO "Sending quote to on-chain node...\n");
    web::http::client::http_client_config cfg;
    cfg.set_timeout(std::chrono::seconds(CLIENT_TIMEOUT));
    web::http::client::http_client *self_api_client = new web::http::client::http_client(get_config()->api_base_url.c_str(), cfg);
    web::uri_builder builder(U("/entry/network"));
    web::http::http_response response;

    // Send quote to validation node, try out 3 times for network error.
    int net_tryout = IAS_TRYOUT;
    while (net_tryout >= 0)
    {
        try
        {
            response = self_api_client->request(web::http::methods::POST, builder.to_string(), b64quote).get();
            break;
        }
        catch (const web::http::http_exception &e)
        {
            cfprintf(felog, CF_ERROR "HTTP Exception: %s\n", e.what());
            cfprintf(felog, CF_INFO "Trying agin:%d\n", net_tryout);
        }
        catch (const std::exception &e)
        {
            cfprintf(felog, CF_ERROR "HTTP throw: %s\n", e.what());
            cfprintf(felog, CF_INFO "Trying agin:%d\n", net_tryout);
        }
        usleep(3000);
        net_tryout--;
    }

    if (response.status_code() != web::http::status_codes::OK)
    {
        cfprintf(felog, CF_ERROR "Entry network failed!\n");
        entry_status = false;
        goto cleanup;
    }

    cfprintf(felog, CF_INFO "Entry network application successfully!\n");

cleanup:

    delete self_api_client;

    return entry_status;
}

/**
 * @description: Execute different session based on parameter
 * @return: session result
 * */
ipc_status_t attest_session()
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    ipc_status_t ipc_status = IPC_SUCCESS;
    if(session_type == SESSION_STARTER)
    {
        sgx_status = attest_session_starter(global_eid, &ipc_status);
    }
    else if(session_type == SESSION_RECEIVER)
    {
        sgx_status = attest_session_receiver(global_eid, &ipc_status);
    }
    else
    {
        return IPC_BADSESSIONTYPE;
    }
    // Judge by result
    if(SGX_SUCCESS == sgx_status)
    {
        if(IPC_SUCCESS !=  ipc_status)
        {
            return ipc_status;
        }
    }
    else
    {
        return IPC_SGX_ERROR;
    }

    return ipc_status;
}

/**
 * @description: start child worker
 */
void start_monitor(void)
{
    cfprintf(NULL, CF_INFO "Monintor process(ID:%d)\n", monitorPID);
    int status = 0;
    pid_t pid = -1;

    // Init IPC
    init_ipc();

    // Init enclave
    if (!initialize_enclave())
    {
        cfprintf(NULL, CF_ERROR "Monitor process init enclave failed!\n");
        exit(3);
    }
    cfprintf(NULL, CF_INFO "Monitor process init enclave successfully!id:%d\n", global_eid);


again:
    // Do TEE key pair transformation
    if(IPC_SUCCESS != attest_session())
    {
        cfprintf(NULL, CF_ERROR "Monitor does local attestation failed!\n");
        //destroy_ipc();
        exit(4);
    }
    cfprintf(NULL, CF_INFO "[Monitor] Do local attestation successfully!\n");

    // Monitor worker process
    monitor_ipc(MONITORTYPE,WORKERTYPE);
    cfprintf(NULL, CF_INFO "Worker process exit unexpectly!Restart it again\n");

    // Deal with child process
    if(!isChild)
    {
        waitpid(workerPID, &status, WNOHANG);
    }

    // Fork new child process
    if((pid=fork()) == -1)
    {
        cfprintf(felog, CF_ERROR "Create worker process failed!\n");
        goto cleanup;
    }

    if(pid == 0)
    {
        cfprintf(NULL, CF_INFO "Start new worker...\n");
        // Child process used for worker
        workerPID = getpid();
        session_type = SESSION_RECEIVER;
        isChild = true;
        start_worker();
    }
    else 
    {
        workerPID = pid;
        session_type = SESSION_STARTER;
        isChild = false;
        goto again;
    }


cleanup:
    /* End and release*/
    sgx_destroy_enclave(global_eid);
    delete get_config();
    close_logfile(felog);

}

/**
 * @description: start parent worker
 */
void start_worker(void)
{
    cfprintf(NULL, CF_INFO "Worker process(ID:%d)\n", workerPID);
    int status = 0;
    pid_t pid = 0;
    pthread_t wthread;
    cfprintf(NULL, CF_INFO "worker global eid:%d\n", global_eid);

    // Init conifigure
    if(!initialize_config())
    {
        cfprintf(felog, CF_ERROR "Init configuration failed!\n");
        return;
    }

    // Init IPC
    init_ipc();

    // Init enclave
    if(global_eid != 0)
    {
        sgx_destroy_enclave(global_eid);
    }
    cfprintf(NULL, CF_INFO "Before Worker process int enclave id:%d\n", global_eid);
    if (!initialize_enclave())
    {
        cfprintf(felog, CF_ERROR "Init enclave failed!\n");
        return;
    }
    cfprintf(NULL, CF_INFO "Worker process int enclave successfully!id:%d\n", global_eid);

    // Entry network
    if (!run_as_server && !entry_network())
    {
        status = -1;
        goto cleanup;
    }

    // Init related components
    if (!initialize_components())
    {
        cfprintf(felog, CF_ERROR "Initial component failed!\n");
        status = -1;
        goto cleanup;
    }

    // Simulate work
    //while(true)
    //{
    //    sleep(50);
    //}

    // Do disk related
    status = pthread_create(&wthread, NULL, do_disk_related, NULL);
    if(status != 0)
    {
        cfprintf(felog, CF_ERROR "Create worker thread failed!\n");
        status = IPC_CREATE_THREAD_ERR;
        goto cleanup;
    }


again:
    // Do TEE key pair transformation
    if(IPC_SUCCESS != attest_session())
    {
        cfprintf(NULL, CF_ERROR "Worker does local attestation failed!\n");
        //destroy_ipc();
        exit(4);
    }
    cfprintf(NULL, CF_INFO "[Worker] Do local attestation successfully!\n");

    // Monitor monitor process
    monitor_ipc(WORKERTYPE,MONITORTYPE);
    cfprintf(NULL, CF_INFO "Monitor process exit unexpectly!Restart it again\n");

    // Deal with child process
    if(!isChild)
    {
        waitpid(monitorPID, &status, WNOHANG);
    }
    
    // Fork a new process for monitor
    if((pid=fork()) == -1)
    {
        cfprintf(felog, CF_ERROR "Create worker process failed!\n");
        status = -1;
        goto cleanup;
    }

    if(pid == 0)
    {
        // Child process used for monitor
        monitorPID = getpid();
        session_type = SESSION_RECEIVER;
        isChild = true;
        start_monitor();
    }
    else
    {
        monitorPID = pid;
        session_type = SESSION_STARTER;
        isChild = false;
        goto again;
    }


cleanup:
    /* End and release*/
    sgx_destroy_enclave(global_eid);
    delete get_config();
    if(ipfs != NULL)
    {
        delete ipfs;
    }
    close_logfile(felog);

    exit(status);
}

void *do_disk_related(void *)
{

/* Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores */
#pragma omp parallel for
    for (size_t i = 0; i < get_config()->empty_capacity; i++)
    {
        ecall_plot_disk(global_eid, get_config()->empty_path.c_str());
    }

    ecall_generate_empty_root(global_eid);

    /* Main validate loop */
    ecall_main_loop(global_eid, get_config()->empty_path.c_str());

    return NULL;
}

/**
 * @description: run main progress
 * @return: exit flag
 */
int main_daemon()
{
    // Clean last time IPC related variable, actually it indicates message queue
    // generated last time without normal exit
    clean_ipc();

    // Create worker process
    monitorPID = getpid();
    pid_t pid;
    if((pid=fork()) == -1)
    {
        cfprintf(NULL, CF_ERROR "Create worker process failed!\n");
        return -1;
    }
    if(pid == 0)
    {
        // Worker process(child process)
        workerPID = getpid();
        session_type = SESSION_STARTER;
        isChild = true;
        start_worker();
    }
    else
    {
        // Monitor process(parent process)
        workerPID = pid;
        session_type = SESSION_RECEIVER;
        isChild = false;
        start_monitor();
    }

    return 1;
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
        cfprintf(felog, CF_ERROR "Init config failed.\n");
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
        cfprintf(felog, CF_ERROR "Init config failed.\n");
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
