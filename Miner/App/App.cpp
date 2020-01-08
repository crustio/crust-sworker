#include "App.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid;
// Indicate if run current process as server
int run_as_server = 0;
// Record monitor and worker process id
pid_t workerPID = -1, monitorPID = -1;
// Local attestation session type
int session_type;
// Local attestation transfered data type
int datatype = IPC_DATATYPE_KEYPAIR;
// Heart beat timeout between monitor and worker process
const int heart_beat_timeout = 30;
// Indicate if entry network has been done
bool is_entried_network = false;
// Indicate if exit whole process
bool exit_process = false;
// Indicate current process in show info
const char *show_tag = "<monitor> ";

Config *p_config = NULL;
ApiHandler *p_api_handler = NULL;
extern FILE *felog;
extern Ipfs *ipfs;

void start_monitor(void);
void start_worker(void);
void *do_disk_related(void *arg);
void app_printf(FILE *stream, const char *type, const char *format, ...);

/**
 * @description: Signal process function to deal with signals transfered
 *  between parent and child process
 * */
static void sig_handler(int signum)
{
    pid_t pid;
    int status;
    switch (signum)
    {
    case SIGUSR1:
        is_entried_network = true;
        break;
    case SIGUSR2:
        exit_process = true;
        break;
    case SIGCHLD:
        /* Deal with child process */
        // Check if there is any child process existed before existing
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        {
            app_printf(felog, CF_INFO, "child %d terminated!\n", pid);
        }
        break;
    }
}

void app_printf(FILE *stream, const char *type, const char *format, ...)
{
    va_list va;
    char *timestr = print_timestamp();
    std::string str;
    str.append(type).append(show_tag).append(format);
    va_start(va, str.c_str());
    vfprintf(stderr, str.c_str(), va);
    va_end(va);

    // Print log in logfile
    if (stream != NULL)
    {
        if (timestr != NULL)
        {
            fprintf(stream, "[%s] ", timestr);
        }
        va_start(va, str.c_str());
        vfprintf(stream, str.c_str(), va);
        va_end(va);
    }
}

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
 * @description: Init configuration
 * @return: Init status
 * */
bool initialize_config(void)
{
    bool status = true;
    // New configure
    if ((p_config = new_config(CONFIG_FILE_PATH)) == NULL)
    {
        app_printf(felog, CF_ERROR, "Init config failed.\n");
        return false;
    }
    p_config->show();

    // Create log file
    if (felog == NULL)
    {
        felog = create_logfile(LOG_FILE_PATH);
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
    app_printf(felog, CF_INFO, "Initial enclave...\n");
    sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO)
    {
        app_printf(felog, CF_ERROR, "This system does not support Intel SGX.\n");
        return -1;
    }
    else
    {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
        {
            app_printf(felog, CF_ERROR, "Intel SGX is supported on this system but disabled in the BIOS\n");
            return -1;
        }
        else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
        {
            app_printf(felog, CF_ERROR, "Intel SGX will be enabled after the next reboot\n");
            return -1;
        }
        else if (!(sgx_support & SGX_SUPPORT_ENABLED))
        {
            app_printf(felog, CF_ERROR, "Intel SGX is supported on this sytem but not available for use. \
                    The system may lock BIOS support, or the Platform Software is not available\n");
            return -1;
        }
    }

    /* Launch the enclave */
    ret = sgx_create_enclave(ENCLAVE_FILE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        app_printf(felog, CF_ERROR, "Init enclave failed.Error code:%08x\n", ret);
        return false;
    }

    /* Generate code measurement */
    if (SGX_SUCCESS != ecall_gen_sgx_measurement(global_eid, &ret))
    {
        app_printf(felog, CF_ERROR, "Generate code measurement failed!error code:%08x\n", ret);
        return false;
    }

    /* Generate ecc key pair */
    if (run_as_server)
    {
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &ret))
        {
            app_printf(felog, CF_ERROR, "Generate key pair failed!\n");
            return false;
        }
    }
    app_printf(felog, CF_INFO, "Initial enclave successfully!\n");

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
    if (new_ipfs(p_config->ipfs_api_base_url.c_str()) == NULL)
    {
        app_printf(felog, CF_ERROR, "Init ipfs failed.\n");
        return false;
    }
    if (!ipfs->is_online())
    {
        app_printf(felog, CF_ERROR, "IPFS daemon is not started up! Please start it up!\n");
        return false;
    }
    //app_printf(felog, CF_INFO, "Init ipfs successfully.\n");

    /* API handler component */
    app_printf(felog, CF_INFO, "Initing api url:%s...\n", p_config->api_base_url.c_str());
    p_api_handler = new ApiHandler(p_config->api_base_url.c_str(), &global_eid);
    if (p_api_handler == NULL)
    {
        app_printf(felog, CF_ERROR, "Init api handler failed.\n");
        return false;
    }
    //app_printf(felog, CF_INFO, "Init api handler successfully.\n");

    if (p_api_handler->start() == -1)
    {
        app_printf(felog, CF_ERROR, "Start network service failed!\n");
        return false;
    }
    //app_printf(felog, CF_INFO, "Start rest service successfully!\n");

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
    uint32_t flags = p_config->flags;
    sgx_quote_nonce_t nonce;
    char *b64quote = NULL;
    char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *)malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char *)spid, p_config->spid.c_str(), p_config->spid.size());
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
        app_printf(felog, CF_ERROR, "sgx_init_quote: %08x\n", status);
        return false;
    }

    status = ecall_get_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        app_printf(felog, CF_ERROR, "get_report: %08x\n", status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        app_printf(felog, CF_ERROR, "sgx_create_report: %08x\n", sgxrv);
        return false;
    }

    // sgx_get_quote_size() has been deprecated, but our PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        app_printf(felog, CF_ERROR, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return false;
    }
    if (status != SGX_SUCCESS)
    {
        app_printf(felog, CF_ERROR, "SGX error while getting quote size: %08x\n", status);
        return false;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        app_printf(felog, CF_ERROR, "out of memory\n");
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
        app_printf(felog, CF_ERROR, "sgx_get_quote: %08x\n", status);
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
        app_printf(felog, CF_ERROR, "Could not base64 encode quote\n");
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
    app_printf(felog, CF_INFO, "Sending quote to on-chain node...\n");
    web::http::client::http_client_config cfg;
    cfg.set_timeout(std::chrono::seconds(CLIENT_TIMEOUT));
    app_printf(felog, CF_INFO, "request url:%s\n", p_config->request_url.c_str());
    web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->request_url.c_str(), cfg);
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
            app_printf(felog, CF_ERROR, "HTTP Exception: %s\n", e.what());
            app_printf(felog, CF_INFO, "Trying agin:%d\n", net_tryout);
        }
        catch (const std::exception &e)
        {
            app_printf(felog, CF_ERROR, "HTTP throw: %s\n", e.what());
            app_printf(felog, CF_INFO, "Trying agin:%d\n", net_tryout);
        }
        usleep(3000);
        net_tryout--;
    }

    if (response.status_code() != web::http::status_codes::OK)
    {
        app_printf(felog, CF_ERROR, "Entry network failed!\n");
        entry_status = false;
        goto cleanup;
    }

    app_printf(felog, CF_INFO, "Entry network application successfully!\n");

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
    if (session_type == SESSION_STARTER)
    {
        sgx_status = ecall_attest_session_starter(global_eid, &ipc_status, datatype);
    }
    else if (session_type == SESSION_RECEIVER)
    {
        sgx_status = ecall_attest_session_receiver(global_eid, &ipc_status, datatype);
    }
    else
    {
        return IPC_BADSESSIONTYPE;
    }
    // Judge by result
    if (SGX_SUCCESS == sgx_status)
    {
        if (IPC_SUCCESS != ipc_status)
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
 * @description: This function used to monitor worker process status,
 *  if worker process is terminated, restart it again
 */
void start_monitor(void)
{
    app_printf(felog, CF_INFO, "Monintor process(ID:%d)\n", monitorPID);
    ipc_status_t ipc_status = IPC_SUCCESS;
    pid_t pid = -1;

    /* Signal function */
    // SIGUSR1 used to notify that entry network has been done,
    // no need to do it again
    signal(SIGUSR1, sig_handler);
    // SIGUSR2 used to notify monitor process to exit
    signal(SIGUSR2, sig_handler);
    signal(SIGCHLD, sig_handler);

    /* Init IPC */
    if (init_ipc() == -1)
    {
        app_printf(felog, CF_ERROR, "Init IPC failed!\n");
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }

    /* Init enclave */
    if (global_eid != 0)
    {
        // If monitor process is copied from fork function,
        // delete copied sgx enclave memory space
        sgx_destroy_enclave(global_eid);
    }
    if (!initialize_enclave())
    {
        app_printf(felog, CF_ERROR, "Monitor process init enclave failed!\n");
        ipc_status = INIT_ENCLAVE_ERROR;
        goto cleanup;
    }
    app_printf(felog, CF_INFO, "Monitor process init enclave successfully!id:%d\n", global_eid);

again:
    /* Do TEE key pair transformation */
    if ((ipc_status = attest_session()) != IPC_SUCCESS)
    {
        app_printf(felog, CF_ERROR, "Do local attestation failed!\n");
        goto cleanup;
    }
    app_printf(felog, CF_INFO, "Do local attestation successfully!\n");

    /* Monitor worker process */
    while (true)
    {
        sleep(heart_beat_timeout);
        if (kill(workerPID, 0) == -1)
        {
            if (errno == ESRCH)
            {
                app_printf(felog, CF_ERROR, "Worker process is not existed!\n");
            }
            else if (errno == EPERM)
            {
                app_printf(felog, CF_ERROR, "Monitor has no right to send sig to worker!\n");
            }
            else if (errno == EINVAL)
            {
                app_printf(felog, CF_ERROR, "Invalid sig!\n");
            }
            else
            {
                app_printf(felog, CF_ERROR, "Unknown error!\n");
            }
            app_printf(felog, CF_ERROR, "Monitor sends sig to worker failed!Error code:%d\n", errno);
            break;
        }
    }
    app_printf(felog, CF_INFO, "Worker process exit unexpectly!Restart it again\n");

    // Check if worker process exit because of entry network or creating work thread failed,
    // then monitor process should end.
    if (exit_process)
    {
        app_printf(felog, CF_ERROR, "Worker process entries network or creates work thread failed! \
                Exit monitor process!\n");
        goto cleanup;
    }

    app_printf(felog, CF_INFO, "Do fork\n");
    /* Fork new child process */
    if ((pid = fork()) == -1)
    {
        app_printf(felog, CF_ERROR, "Create worker process failed!\n");
        ipc_status = FORK_NEW_PROCESS_ERROR;
        goto cleanup;
    }

    if (pid == 0)
    {
        // Child process used for worker
        app_printf(felog, CF_INFO, "Start new worker...\n");
        show_tag = "<worker> ";
        workerPID = getpid();
        session_type = SESSION_RECEIVER;
        start_worker();
    }
    else
    {
        workerPID = pid;
        session_type = SESSION_STARTER;
        goto again;
    }

cleanup:
    /* End and release*/
    if (global_eid != 0)
    {
        sgx_destroy_enclave(global_eid);
    }
    close_logfile(felog);
    destroy_ipc();

    app_printf(felog, CF_ERROR, "Monitor process exits with error code:%lx\n", ipc_status);

    exit(ipc_status);
}

// TODO: move to other files
/**
 * @description: start parent worker
 */
void start_worker(void)
{
    app_printf(felog, CF_INFO, "Worker process(ID:%d)\n", workerPID);
    pid_t pid = 0;
    pthread_t wthread;
    ipc_status_t ipc_status = IPC_SUCCESS;
    app_printf(felog, CF_INFO, "Worker global eid:%d\n", global_eid);

    /* Signal function */
    // SIGUSR1 used to notify that entry network has been done,
    // no need to do it again
    signal(SIGUSR1, sig_handler);
    signal(SIGCHLD, sig_handler);

    /* Init conifigure */
    if (!initialize_config())
    {
        app_printf(felog, CF_ERROR, "Init configuration failed!\n");
        exit(INIT_CONFIG_ERROR);
    }

    /* Init related components */
    if (!initialize_components())
    {
        app_printf(felog, CF_ERROR, "Init component failed!\n");
        ipc_status = INIT_COMPONENT_ERROR;
        goto cleanup;
    }
    app_printf(felog, CF_INFO, "Init components successfully!\n");

    /* Init IPC */
    if (init_ipc() == -1)
    {
        app_printf(felog, CF_ERROR, "Init IPC failed!\n");
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }
    app_printf(felog, CF_INFO, "Init IPC successfully!\n");

    /* Init enclave */
    if (global_eid != 0)
    {
        // If worker process is copied from fork function,
        // delete copied sgx enclave memory space
        sgx_destroy_enclave(global_eid);
    }
    if (!initialize_enclave())
    {
        app_printf(felog, CF_ERROR, "Init enclave failed!\n");
        ipc_status = INIT_ENCLAVE_ERROR;
        goto cleanup;
    }
    app_printf(felog, CF_INFO, "Worker process int enclave successfully!id:%d\n", global_eid);

    /* Do TEE key pair transformation */
    if ((ipc_status = attest_session()) != IPC_SUCCESS)
    {
        app_printf(felog, CF_ERROR, "Do local attestation failed!\n");
        goto cleanup;
    }
    app_printf(felog, CF_INFO, "Do local attestation successfully!\n");

    /* Entry network */
    if (!is_entried_network && !run_as_server && !entry_network())
    {
        ipc_status = ENTRY_NETWORK_ERROR;
        goto cleanup;
    }
    if (!is_entried_network && kill(monitorPID, SIGUSR1) == -1)
    {
        app_printf(felog, CF_ERROR, "Send entry network status failed!\n");
    }

    /* Do disk related */
    if (pthread_create(&wthread, NULL, do_disk_related, NULL) != 0)
    {
        app_printf(felog, CF_ERROR, "Create worker thread failed!\n");
        ipc_status = IPC_CREATE_THREAD_ERR;
        goto cleanup;
    }

again:
    /* Monitor monitor process */
    while (true)
    {
        sleep(heart_beat_timeout);
        if (kill(monitorPID, 0) == -1)
        {
            if (errno == ESRCH)
            {
                app_printf(felog, CF_ERROR, "Monitor process is not existed!\n");
            }
            else if (errno == EPERM)
            {
                app_printf(felog, CF_ERROR, "Worker has no right to send sig to worker!\n");
            }
            else if (errno == EINVAL)
            {
                app_printf(felog, CF_ERROR, "Invalid sig!\n");
            }
            else
            {
                app_printf(felog, CF_ERROR, "Unknown error!\n");
            }
            app_printf(felog, CF_ERROR, "Worker sends sig to worker failed!Error code:%d\n", errno);
            break;
        }
    }
    app_printf(felog, CF_INFO, "Monitor process exit unexpectly!Restart it again\n");

    /* Fork a new process for monitor */
    if ((pid = fork()) == -1)
    {
        app_printf(felog, CF_ERROR, "Create worker process failed!\n");
        ipc_status = FORK_NEW_PROCESS_ERROR;
        goto cleanup;
    }

    if (pid == 0)
    {
        // Child process used for monitor
        show_tag = "<monitor> ";
        monitorPID = getpid();
        session_type = SESSION_RECEIVER;
        start_monitor();
    }
    else
    {
        monitorPID = pid;
        session_type = SESSION_STARTER;
        /* Do TEE key pair transformation */
        if ((ipc_status = attest_session()) != IPC_SUCCESS)
        {
            app_printf(felog, CF_ERROR, "Do local attestation failed!\n");
            goto cleanup;
        }
        app_printf(felog, CF_INFO, "Do local attestation successfully!\n");
        goto again;
    }

cleanup:
    /* End and release */
    delete ipfs;
    delete p_api_handler;
    delete p_config;
    destroy_ipc();
    close_logfile(felog);
    if (global_eid != 0)
    {
        sgx_destroy_enclave(global_eid);
    }

    // If entry network or create work thread failed, notify monitor process to exit
    if (ENTRY_NETWORK_ERROR == ipc_status || IPC_CREATE_THREAD_ERR == ipc_status)
    {
        kill(monitorPID, SIGUSR2);
    }

    app_printf(felog, CF_ERROR, "Worker process exits with error code:%lx\n", ipc_status);

    exit(ipc_status);
}

void *do_disk_related(void *)
{

/* Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores */
#pragma omp parallel for
    for (size_t i = 0; i < p_config->empty_capacity; i++)
    {
        ecall_plot_disk(global_eid, p_config->empty_path.c_str());
    }

    ecall_generate_empty_root(global_eid);

    /* Main validate loop */
    ecall_main_loop(global_eid, p_config->empty_path.c_str());

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
    if ((pid = fork()) == -1)
    {
        app_printf(felog, CF_ERROR, "Create worker process failed!\n");
        return -1;
    }
    if (pid == 0)
    {
        // Worker process(child process)
        show_tag = "<worker> ";
        workerPID = getpid();
        session_type = SESSION_STARTER;
        start_worker();
    }
    else
    {
        // Monitor process(parent process)
        show_tag = "<monitor> ";
        workerPID = pid;
        session_type = SESSION_RECEIVER;
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
        app_printf(felog, CF_ERROR, "Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->api_base_url.c_str());
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
        app_printf(felog, CF_ERROR, "Init config failed.\n");
        return false;
    }

    /* Call internal api interface to get information */
    web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->api_base_url.c_str());
    web::uri_builder builder(U("/report"));
    builder.append_query("block_hash", block_hash);
    web::http::http_response response = self_api_client->request(web::http::methods::GET, builder.to_string()).get();
    printf("%s", response.extract_utf8string().get().c_str());
    delete self_api_client;
    return 0;
}
