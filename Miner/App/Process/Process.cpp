#include "Process.h"
#include "OCalls.h"
#include <map>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid;
// Indicate if run current process as server
// Record monitor and worker process id
pid_t workerPID=-1,monitorPID=-1,monitorPID2=-1;
// Local attestation session type
int session_type;
// Local attestation transfered data type
int datatype = IPC_DATATYPE_KEYPAIR;
// Heart beat timeout between monitor and worker process
const int heart_beat_timeout = 15;
// Indicate if entry network has been done
bool is_entried_network = false;
// Indicate if exit whole process
bool exit_process = false;
// Indicate current process in show info
const char *show_tag = "<monitor>";
// Pointor to configure instance
Config *p_config = NULL;
// Pointer to http handler instance
ApiHandler *p_api_handler = NULL;

extern FILE *felog;
extern bool run_as_server;
extern int msqid;
extern msg_form msg;


void start_monitor(void);
void start_monitor2(void);
void start_worker(void);
ipc_status_t attest_session();


/**
 * @description: Printf process related information
 * */
/*
void cfprintf(FILE *stream, const char* type, const char *format, ...)
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
        if(timestr != NULL)
        {
		    fprintf(stream, "[%s] ", timestr);
        }
	    va_start(va, str.c_str());
	    vfprintf(stream, str.c_str(), va);
	    va_end(va);
	}
}
*/

/**
 * @description: Signal process function to deal with signals transfered
 *  between parent and child process
 * */
static void sig_handler(int signum)
{
    pid_t pid;
    int status;
    switch(signum)
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
            while((pid=waitpid(-1, &status, WNOHANG)) > 0)
            {
                cfprintf(felog, CF_INFO "%s child %d terminated!Error code:%lx\n", show_tag, pid, status);
            }
            break;
    }
}

/**
 * @description: Init configuration
 * @return: Init status
 * */
bool initialize_config(void)
{
    // New configure
    p_config = Config::get_instance();
    if(p_config == NULL)
    {
        return false;
    }
    p_config->show();

    return true;
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
    cfprintf(felog, CF_INFO "%s Initial enclave...\n", show_tag);
    sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO)
    {
        cfprintf(felog, CF_ERROR "%s This system does not support Intel SGX.\n", show_tag);
        return -1;
    }
    else
    {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
        {
            cfprintf(felog, CF_ERROR "%s Intel SGX is supported on this system but disabled in the BIOS\n", show_tag);
            return -1;
        }
        else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
        {
            cfprintf(felog, CF_ERROR "%s Intel SGX will be enabled after the next reboot\n", show_tag);
            return -1;
        }
        else if (!(sgx_support & SGX_SUPPORT_ENABLED))
        {
            cfprintf(felog, CF_ERROR "%s Intel SGX is supported on this sytem but not available for use. \
                    The system may lock BIOS support, or the Platform Software is not available\n", show_tag);
            return -1;
        }
    }

    /* Launch the enclave */
    ret = sgx_create_enclave(ENCLAVE_FILE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "%s Init enclave failed.Error code:%08x\n", show_tag, ret);
        return false;
    }

    /* Generate code measurement */
    if (SGX_SUCCESS != ecall_gen_sgx_measurement(global_eid, &ret))
    {
        cfprintf(felog, CF_ERROR "%s Generate code measurement failed!error code:%08x\n", show_tag, ret);
        return false;
    }

    /* Generate ecc key pair */
    if (run_as_server)
    {
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &ret))
        {
            cfprintf(felog, CF_ERROR "%s Generate key pair failed!\n", show_tag);
            return false;
        }
    }
    cfprintf(felog, CF_INFO "%s Initial enclave successfully!\n", show_tag);

    return true;
}

/**
 * @description: initialize the components:
 *   config -> user configurations and const configurations
 *   ipfs -> used to store meaningful files, please make sure ipfs is running before running daemon
 *   api handler -> external API interface 
 * @return: success or failure
 */
bool initialize_components(void)
{
    /* IPFS component */
    if(new_ipfs(p_config->ipfs_api_base_url.c_str()) == NULL)
    {
        cfprintf(felog, CF_ERROR "%s Init ipfs failed.\n", show_tag);
        return false;
    }

    if(!get_ipfs()->is_online())
    {
        cfprintf(felog, CF_ERROR "%s ipfs daemon is not started up! Please start it up!\n", show_tag);
        return false;
    }
    //cfprintf(felog, CF_INFO "%s Init ipfs successfully.\n", show_tag);

    /* Crust component */
    if(new_crust(p_config->crust_api_base_url.c_str()) == NULL)
    {
        cfprintf(felog, CF_ERROR "%s Init crust failed.\n", show_tag);
        return false;
    }

    if(!get_crust()->is_online())
    {
        cfprintf(felog, CF_ERROR "%s crust api or crust chain is not started up! Please start it up!\n", show_tag);
        return false;
    }

    /* API handler component */
    cfprintf(felog, CF_INFO "%s Initing api url:%s...\n", show_tag, p_config->api_base_url.c_str());
    p_api_handler = new ApiHandler(p_config->api_base_url.c_str(), &global_eid);
    if(p_api_handler == NULL)
    {
        cfprintf(felog, CF_ERROR "%s Init api handler failed.\n", show_tag);
        return false;
    }
    //cfprintf(felog, CF_INFO "%s Init api handler successfully.\n", show_tag);

    if(p_api_handler->start() == -1)
    {
        cfprintf(felog, CF_ERROR "%s Start network service failed!\n", show_tag);
        return false;
    }
    cfprintf(felog, CF_INFO "%s Start rest service successfully!\n", show_tag);

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
    //uint32_t flags = Config::flags;
    sgx_quote_nonce_t nonce;
    char *b64quote = NULL;
    char *b64manifest = NULL;
    sgx_spid_t *spid = (sgx_spid_t *)malloc(sizeof(sgx_spid_t));
    memset(spid, 0, sizeof(sgx_spid_t));
    from_hexstring((unsigned char *)spid, p_config->spid.c_str(), p_config->spid.size());
    //from_hexstring((unsigned char *)spid, Config::spid.c_str(), Config::spid.size());
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
            return false;
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
        cfprintf(felog, CF_ERROR "%s sgx_init_quote: %08x\n", show_tag, status);
        return false;
    }

    status = ecall_get_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "%s get_report: %08x\n", show_tag, status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "%s sgx_create_report: %08x\n", show_tag, sgxrv);
        return false;
    }

    // sgx_get_quote_size() has been deprecated, but our PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        cfprintf(felog, CF_ERROR "%s PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n", show_tag);
        return false;
    }
    if (status != SGX_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "%s SGX error while getting quote size: %08x\n", show_tag, status);
        return false;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        cfprintf(felog, CF_ERROR "%s out of memory\n", show_tag);
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
        cfprintf(felog, CF_ERROR "%s sgx_get_quote: %08x\n", show_tag, status);
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
        cfprintf(felog, CF_ERROR "%s Could not base64 encode quote\n", show_tag);
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
    cfprintf(felog, CF_INFO "%s Sending quote to on-chain node...\n", show_tag);
    web::http::client::http_client_config cfg;
    cfg.set_timeout(std::chrono::seconds(CLIENT_TIMEOUT));
    cfprintf(felog, CF_INFO "%s request url:%s\n", show_tag, p_config->request_url.c_str());
    //cfprintf(felog, CF_INFO "%s request url:%s\n", show_tag, Config::request_url.c_str());
    web::http::client::http_client *self_api_client = new web::http::client::http_client(p_config->request_url.c_str(), cfg);
    //web::http::client::http_client *self_api_client = new web::http::client::http_client(Config::request_url.c_str(), cfg);
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
            cfprintf(felog, CF_ERROR "%s HTTP Exception: %s\n", show_tag, e.what());
            cfprintf(felog, CF_INFO "%s Trying agin:%d\n", show_tag, net_tryout);
        }
        catch (const std::exception &e)
        {
            cfprintf(felog, CF_ERROR "%s HTTP throw: %s\n", show_tag, e.what());
            cfprintf(felog, CF_INFO "%s Trying agin:%d\n", show_tag, net_tryout);
        }
        sleep(1);
        net_tryout--;
    }

    if (response.status_code() != web::http::status_codes::OK)
    {
        cfprintf(felog, CF_ERROR "%s Entry network failed!\n", show_tag);
        entry_status = false;
        goto cleanup;
    }

    cfprintf(felog, CF_INFO "%s Entry network application successfully!\n", show_tag);

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
        cfprintf(felog, CF_INFO "%s do attestation....\n", show_tag);
        sgx_status = ecall_attest_session_starter(global_eid, &ipc_status, datatype);
    }
    else if(session_type == SESSION_RECEIVER)
    {
        sgx_status = ecall_attest_session_receiver(global_eid, &ipc_status, datatype);
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
 * @description: Do ploting disk related
 * */
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
    //ecall_main_loop(global_eid, Config::empty_path.c_str());

    return NULL;
}

/**
 * @description: This function used to monitor worker process status,
 *  if worker process is terminated, restart it again
 */
void start_monitor(void)
{
    cfprintf(felog, CF_INFO "%s Monintor process(ID:%d)\n", show_tag, monitorPID);
    ipc_status_t ipc_status = IPC_SUCCESS;
    pid_t pid = -1;
    std::map<std::string,pid_t> pids_m;
    pids_m["worker"] = workerPID;
    pids_m["monitor2"] = monitorPID2;
    bool is_break_check = false;
    bool doAttest = true;   // Used to indicate if worker terminated
    std::pair<std::string,pid_t> exit_entry;

    /* Signal function */
    // SIGUSR1 used to notify that entry network has been done,
    // no need to do it again
    signal(SIGUSR1, sig_handler);
    // SIGUSR2 used to notify monitor process to exit
    signal(SIGUSR2, sig_handler);
    signal(SIGCHLD, sig_handler);

    /* Init IPC */
    if(init_ipc() == -1)
    {
        cfprintf(felog, CF_ERROR "%s Init IPC failed!\n", show_tag);
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }

    /* Init enclave */
    if(global_eid != 0)
    {
        // If monitor process is copied from fork function,
        // delete copied sgx enclave memory space
        sgx_destroy_enclave(global_eid);
    }
    if (!initialize_enclave())
    {
        cfprintf(felog, CF_ERROR "%s Monitor process init enclave failed!\n", show_tag);
        ipc_status = INIT_ENCLAVE_ERROR;
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "%s Monitor process init enclave successfully!id:%d\n", show_tag, global_eid);


again:
    /* Do local attestation and exchange pid with worker */
    if(doAttest)
    {
        if((ipc_status=attest_session()) != IPC_SUCCESS)
        {
            cfprintf(felog, CF_ERROR "%s Do local attestation failed!\n", show_tag);
            goto cleanup;
        }
        else
        {
            cfprintf(felog, CF_INFO "%s Do local attestation successfully!\n", show_tag);
            /* Exchange pid with worker */
            msg.type = 201;
            msg.text = getpid();
            if(msgsnd(msqid, &msg, sizeof(msg.text), 0) == -1)
            {
                cfprintf(felog, CF_ERROR "%s Send monitor pid failed!\n", show_tag);
            }
            if(Msgrcv_to(msqid, &msg, sizeof(msg.text), 200) == -1)
            {
                cfprintf(felog, CF_ERROR "%s Get worker pid failed!!\n", show_tag);
            }
            else
            {
                workerPID = msg.text;
                pids_m["worker"] = workerPID;
                cfprintf(felog, CF_INFO "%s Get worker pid successfully!pid:%d\n", show_tag, workerPID);
            }
        }
        doAttest = false;
    }

    /* Monitor worker and monitor2 process */
    while(true)
    {
        sleep(heart_beat_timeout);
        for(auto it : pids_m)
        {
            if(kill(it.second, 0) == -1)
            {
                if(errno == ESRCH)
                {
                    cfprintf(felog, CF_ERROR "%s %s process is not existed!pid:%d\n", show_tag, it.first.c_str(), it.second);
                }
                else if(errno == EPERM)
                {
                    cfprintf(felog, CF_ERROR "%s %s has no right to send sig to worker!\n", show_tag, it.first.c_str());
                }
                else if(errno == EINVAL)
                {
                    cfprintf(felog, CF_ERROR "%s Invalid sig!\n", show_tag);
                }
                else
                {
                    cfprintf(felog, CF_ERROR "%s Unknown error!\n", show_tag);
                }
                cfprintf(felog, CF_ERROR "%s %s sends sig to worker failed!Error code:%d\n", show_tag, it.first.c_str(), errno);
                is_break_check = true;
                exit_entry = it;
                break;
            }
        }
        if(is_break_check) break;
    }
    is_break_check = false;
    cfprintf(felog, CF_INFO "%s %s process exit unexpectly!Restart it again\n", show_tag, exit_entry.first.c_str());

    // Check if worker process exit because of entry network or creating work thread failed,
    // then monitor process should end.
    if(exit_process)
    {
        cfprintf(felog, CF_ERROR "%s Worker process entries network or creates work thread failed! \
                Exit monitor process!\n", show_tag);
        goto cleanup;
    }

    /* Fork new child process */
    cfprintf(felog, CF_INFO "%s Do fork\n", show_tag);
    // Should get current pid before fork
    monitorPID = getpid();
    if((pid=fork()) == -1)
    {
        cfprintf(felog, CF_ERROR "%s Create worker process failed!\n", show_tag);
        ipc_status = FORK_NEW_PROCESS_ERROR;
        goto cleanup;
    }

    if(pid == 0)
    {
        // Child process used for worker
        cfprintf(felog, CF_INFO "%s Start new %s...\n", show_tag, exit_entry.first.c_str());
        show_tag = ("<" + exit_entry.first + ">").c_str();
        if(exit_entry.first.compare("worker") == 0)
        {
            session_type = SESSION_RECEIVER;
            workerPID = getpid();
            start_worker();
        }
        else if(exit_entry.first.compare("monitor2") == 0)
        {
            monitorPID2 = getpid();
            start_monitor2();
        }
        else
        {
            cfprintf(NULL, CF_ERROR "Unknown process!\n");
            goto cleanup;
        }
    }
    else 
    {
        if(exit_entry.first.compare("worker") == 0)
        {
            workerPID = pid;
            session_type = SESSION_STARTER;
            doAttest = true;
        }
        else if(exit_entry.first.compare("monitor2") == 0)
        {
            monitorPID2 = pid;
        }
        else
        {
            cfprintf(NULL, CF_ERROR "Unknown process!\n");
            goto cleanup;
        }
        // Update related pid
        pids_m[exit_entry.first] = pid;
        goto again;
    }


cleanup:
    /* End and release*/
    if(global_eid != 0)
    {
        sgx_destroy_enclave(global_eid);
    }
    close_logfile(felog);
    destroy_ipc();

    cfprintf(felog, CF_ERROR "%s Monitor process exits with error code:%lx\n", show_tag, ipc_status);

    // Send SIGKILL to monitor2 to prevent it starts up monitor again
    if(kill(monitorPID2, SIGKILL) == -1)
    {
        cfprintf(NULL, CF_ERROR "Send SIGKILL to monitor2 failed!\n");
    }

    exit(ipc_status);
}

/**
 * @description: Start monitor2 process used to monitor monitor process
 * */
void start_monitor2(void)
{
    cfprintf(felog, CF_INFO "%s Monintor2 process(ID:%d)\n", show_tag, monitorPID2);
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
    if(init_ipc() == -1)
    {
        cfprintf(felog, CF_ERROR "%s Init IPC failed!\n", show_tag);
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }


again:
    /* Monitor worker process */
    while(true)
    {
        sleep(heart_beat_timeout);
        if(kill(monitorPID, 0) == -1)
        {
            if(errno == ESRCH)
            {
                cfprintf(felog, CF_ERROR "%s Monitor process is not existed!\n", show_tag);
            }
            else if(errno == EPERM)
            {
                cfprintf(felog, CF_ERROR "%s Monitor2 has no right to send sig to monitor!\n", show_tag);
            }
            else if(errno == EINVAL)
            {
                cfprintf(felog, CF_ERROR "%s Invalid sig!\n", show_tag);
            }
            else
            {
                cfprintf(felog, CF_ERROR "%s Unknown error!\n", show_tag);
            }
            cfprintf(felog, CF_ERROR "%s Monitor2 sends sig to monitor failed!Error code:%d\n", show_tag, errno);
            break;
        }
    }
    cfprintf(felog, CF_INFO "%s Monitor process exit unexpectly!Restart it again\n", show_tag);

    // Check if worker process exit because of entry network or creating work thread failed,
    // then monitor process should end.
    if(exit_process)
    {
        cfprintf(felog, CF_ERROR "%s Monitor process entries network or creates work thread failed! \
                Exit monitor2 process!\n", show_tag);
        goto cleanup;
    }

    /* Fork new child process */
    cfprintf(felog, CF_INFO "%s Do fork\n", show_tag);
    // Should get current pid before fork
    monitorPID2 = getpid();
    if((pid=fork()) == -1)
    {
        cfprintf(felog, CF_ERROR "%s Create monitor process failed!\n", show_tag);
        ipc_status = FORK_NEW_PROCESS_ERROR;
        goto cleanup;
    }
    if(pid == 0)
    {
        // Child process used for worker
        cfprintf(felog, CF_INFO "%s Start new monitor:monitor2:%d...\n", show_tag, monitorPID2);
        show_tag = "<monitor>";
        session_type = SESSION_RECEIVER;
        start_monitor();
    }
    else 
    {
        monitorPID = pid;
        goto again;
    }


cleanup:
    /* End and release*/
    close_logfile(felog);
    destroy_ipc();

    cfprintf(felog, CF_ERROR "%s Monitor process exits with error code:%lx\n", show_tag, ipc_status);

    exit(ipc_status);
}

/**
 * @description: start parent worker
 */
void start_worker(void)
{
    cfprintf(felog, CF_INFO "%s Worker process(ID:%d)\n", show_tag, workerPID);
    pthread_t wthread;
    ipc_status_t ipc_status = IPC_SUCCESS;
    cfprintf(felog, CF_INFO "%s Worker global eid:%d\n", show_tag, global_eid);

    /* Signal function */
    // SIGUSR1 used to notify that entry network has been done,
    // no need to do it again
    signal(SIGUSR1, sig_handler);
    // If monitor exit unexpectly, monitor will notify worker to do attestation again
    signal(SIGUSR2, sig_handler);
    signal(SIGCHLD, sig_handler);

    /* Init conifigure */
    if(!initialize_config())
    {
        cfprintf(felog, CF_ERROR "%s Init configuration failed!\n", show_tag);
        exit(INIT_CONFIG_ERROR);
    }

    /* Init related components */
    if(!initialize_components())
    {
        cfprintf(felog, CF_ERROR "%s Init component failed!\n", show_tag);
        ipc_status = INIT_COMPONENT_ERROR;
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "%s Init components successfully!\n", show_tag);

    /* Init IPC */
    if(init_ipc() == -1)
    {
        cfprintf(felog, CF_ERROR "%s Init IPC failed!\n", show_tag);
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "%s Init IPC successfully!\n", show_tag);

    /* Init enclave */
    if(global_eid != 0)
    {
        // If worker process is copied from fork function,
        // delete copied sgx enclave memory space
        sgx_destroy_enclave(global_eid);
    }
    if (!initialize_enclave())
    {
        cfprintf(felog, CF_ERROR "%s Init enclave failed!\n", show_tag);
        ipc_status = INIT_ENCLAVE_ERROR;
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "%s Worker process int enclave successfully!id:%d\n", show_tag, global_eid);

    /* Do TEE key pair transformation */
    if((ipc_status=attest_session()) != IPC_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "%s Do local attestation failed!\n", show_tag);
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "%s Do local attestation successfully!\n", show_tag);

    /* Entry network */
    if(!is_entried_network && !run_as_server && !entry_network())
    {
        ipc_status = ENTRY_NETWORK_ERROR;
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "Entrying network...\n");
    if(!is_entried_network)
    {
        if(kill(monitorPID, SIGUSR1) == -1)
        {
            cfprintf(felog, CF_ERROR "%s Send entry network status failed!\n", show_tag);
        }
        else
        {
            is_entried_network = true;
        }
    }

    /* Do disk related */
    cfprintf(felog, CF_INFO "Ploting disk...\n");
    if(pthread_create(&wthread, NULL, do_disk_related, NULL) != 0)
    {
        cfprintf(felog, CF_ERROR "%s Create worker thread failed!\n", show_tag);
        ipc_status = IPC_CREATE_THREAD_ERR;
        goto cleanup;
    }


again:
    /* Exchange pid with monitor */
    msg.type = 200;
    msg.text = getpid();
    if(msgsnd(msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        cfprintf(felog, CF_ERROR "%s Send monitor pid failed!\n", show_tag);
    }
    if(Msgrcv_to(msqid, &msg, sizeof(msg.text), 201) == -1)
    {
        cfprintf(felog, CF_ERROR "%s Get monitor pid failed!!\n", show_tag);
    }
    else
    {
        monitorPID = msg.text;
        cfprintf(felog, CF_INFO "%s Get monitor pid successfully!pid:%d\n", show_tag, monitorPID);
    }

    /* Monitor worker process */
    while(true)
    {
        sleep(heart_beat_timeout);
        if(kill(monitorPID, 0) == -1)
        {
            if(errno == ESRCH)
            {
                cfprintf(felog, CF_ERROR "%s Monitor process is not existed!\n", show_tag);
            }
            else if(errno == EPERM)
            {
                cfprintf(felog, CF_ERROR "%s Worker has no right to send sig to monitor!\n", show_tag);
            }
            else if(errno == EINVAL)
            {
                cfprintf(felog, CF_ERROR "%s Invalid sig!\n", show_tag);
            }
            else
            {
                cfprintf(felog, CF_ERROR "%s Unknown error!\n", show_tag);
            }
            cfprintf(felog, CF_ERROR "%s Worker sends sig to monitor failed!Error code:%d\n", show_tag, errno);
            break;
        }
    }

    /* Do TEE key pair transformation */
    session_type = SESSION_STARTER;
    if((ipc_status=attest_session()) != IPC_SUCCESS)
    {
        cfprintf(felog, CF_ERROR "%s Do local attestation failed!\n", show_tag);
        goto cleanup;
    }
    cfprintf(felog, CF_INFO "%s Do local attestation successfully!\n", show_tag);

    goto again;


cleanup:
    /* End and release */
    delete p_config;
    delete get_ipfs();
    p_api_handler->stop();
    delete p_api_handler;
    destroy_ipc();
    close_logfile(felog);
    if(global_eid != 0)
    {
        sgx_destroy_enclave(global_eid);
    }

    // If entry network or create work thread failed, notify monitor process to exit
    if(ENTRY_NETWORK_ERROR == ipc_status || IPC_CREATE_THREAD_ERR == ipc_status || INIT_COMPONENT_ERROR == ipc_status)
    {
        kill(monitorPID, SIGUSR2);
    }

    cfprintf(felog, CF_ERROR "%s Worker process exits with error code:%lx\n", show_tag, ipc_status);

    exit(ipc_status);
}

/**
 * @desination: Main function to start application
 * @return: Start status
 * */
int process()
{
    // Clean last time IPC related variable, actually it indicates message queue
    // generated last time without normal exit
    clean_ipc();

    // Create log file
    if(felog == NULL)
    {
        felog = create_logfile(LOG_FILE_PATH);
    }

    // Create worker process
    monitorPID = getpid();
    pid_t pid;
    if((pid=fork()) == -1)
    {
        cfprintf(felog, CF_ERROR "%s Create worker process failed!\n", show_tag);
        return -1;
    }
    if(pid == 0)
    {
        // Worker process(child process)
        show_tag = "<worker>";
        session_type = SESSION_STARTER;
        workerPID = getpid();
        start_worker();
    }
    else
    {
        // Monitor process(parent process)
        show_tag = "<monitor>";
        workerPID = pid;
        if((pid=fork()) == -1)
        {
            cfprintf(felog, CF_ERROR "%s Create worker process failed!\n", show_tag);
            return -1;
        }
        if(pid == 0)
        {
            show_tag = "<monitor2>";
            monitorPID2 = getpid();
            start_monitor2();
        }
        else
        {
            monitorPID2 = pid;
            session_type = SESSION_RECEIVER;
            start_monitor();
        }
    }

    return 1;
}
