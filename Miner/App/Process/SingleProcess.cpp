#include "SingleProcess.h"
#include "OCalls.h"
#include <map>
#include <fstream>

#define RECEIVE_PID_RETRY 30
#define IPC_RETRY 10

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid;
// Heart beat timeout between monitor and worker process
const int heart_beat_timeout = 15;
// Pointor to configure instance
Config *p_config = NULL;
// Pointer to http handler instance
ApiHandler *p_api_handler = NULL;

/* Should be shared between monitor and worker */
// Store tee identity
std::string g_entry_net_res = "";

extern FILE *felog;
extern bool run_as_server;
extern bool offline_chain_mode;

void start(void);
bool wait_chain_run_s(void);
bool do_plot_disk_s(void);

/**
 * @description: Init configuration
 * @return: Init status
 * */
bool initialize_config_s(void)
{
    // New configure
    p_config = Config::get_instance();
    if (p_config == NULL)
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
bool initialize_enclave_s()
{
    int sgx_support;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Can we run SGX? */
    cprintf_info(felog, "Initial enclave...\n");
    sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO)
    {
        cprintf_err(felog, "This system does not support Intel SGX.\n");
        return -1;
    }
    else
    {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
        {
            cprintf_err(felog, "Intel SGX is supported on this system but disabled in the BIOS\n");
            return -1;
        }
        else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
        {
            cprintf_err(felog, "Intel SGX will be enabled after the next reboot\n");
            return -1;
        }
        else if (!(sgx_support & SGX_SUPPORT_ENABLED))
        {
            cprintf_err(felog, "Intel SGX is supported on this sytem but not available for use. \
                    The system may lock BIOS support, or the Platform Software is not available\n");
            return -1;
        }
    }

    /* Launch the enclave */
    ret = sgx_create_enclave(ENCLAVE_FILE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        cprintf_err(felog, "Init enclave failed.Error code:%08x\n", ret);
        return false;
    }

    /* Generate code measurement */
    if (SGX_SUCCESS != ecall_gen_sgx_measurement(global_eid, &ret))
    {
        cprintf_err(felog, "Generate code measurement failed!error code:%08x\n", ret);
        return false;
    }

    /* Set application run mode */
    if (SGX_SUCCESS != ecall_set_run_mode(global_eid, APP_RUN_MODE_SINGLE, strlen(APP_RUN_MODE_SINGLE)))
    {
        cprintf_err(felog, "Set TEE run mode failed!\n");
        return false;
    }

    cprintf_info(felog, "Initial enclave successfully!Enclave id:%d\n", global_eid);

    return true;
}

/**
 * @description: Start http service
 * */
void *start_http_s(void *)
{
    /* API handler component */
    cprintf_info(felog, "Initing api url:%s...\n", p_config->api_base_url.c_str());
    p_api_handler = new ApiHandler(&global_eid);
    if (p_api_handler == NULL)
    {
        cprintf_err(felog, "Init api handler failed.\n");
        return NULL;
    }
    //cprintf_info(felog, "Init api handler successfully.\n");
    p_api_handler->start();
    cprintf_err(felog, "Start network service failed!\n");
    return NULL;
}

/**
 * @description: initialize the components:
 *   config -> user configurations and const configurations
 *   ipfs -> used to store meaningful files, please make sure ipfs is running before running daemon
 *   api handler -> external API interface 
 * @return: success or failure
 */
bool initialize_components_s(void)
{
    /* IPFS component */
    if (new_ipfs(p_config->ipfs_api_base_url.c_str()) == NULL)
    {
        cprintf_err(felog, "Init ipfs failed.\n");
        return false;
    }

    if (!get_ipfs()->is_online())
    {
        cprintf_err(felog, "ipfs daemon is not started up! Please start it up!\n");
        return false;
    }

    pthread_t wthread;
    if (pthread_create(&wthread, NULL, start_http_s, NULL) != 0)
    {
        cprintf_err(felog, "Create rest service thread failed!\n");
        return false;
    }
    cprintf_info(felog, "Start rest service successfully!\n");

    cprintf_info(felog, "Init components successfully!\n");

    return true;
}

/*
 * @description: entry network off-chain node sends quote to onchain node
 *   to verify identity
 * @return: success or failure
 * */
bool entry_network_s()
{
    sgx_quote_sign_type_t linkable = SGX_UNLINKABLE_SIGNATURE;
    sgx_status_t status, sgxrv;
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
            return false;
        }
    }

    if (OPT_ISSET(flags, OPT_LINK))
    {
        linkable = SGX_LINKABLE_SIGNATURE;
    }

    /* Get our quote */
    memset(&report, 0, sizeof(report));

    status = sgx_init_quote(&target_info, &epid_gid);
    if (status != SGX_SUCCESS)
    {
        cprintf_err(felog, "sgx_init_quote: %08x\n", status);
        return false;
    }

    status = ecall_get_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        cprintf_err(felog, "get_report: %08x\n", status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        cprintf_err(felog, "sgx_create_report: %08x\n", sgxrv);
        return false;
    }

    // sgx_get_quote_size() has been deprecated, but our PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        cprintf_err(felog, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return false;
    }
    if (status != SGX_SUCCESS)
    {
        cprintf_err(felog, "SGX error while getting quote size: %08x\n", status);
        return false;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        cprintf_err(felog, "out of memory\n");
        return false;
    }

    memset(quote, 0, sz);
    fprintf(felog, "========== linkable: %d\n", linkable);
    fprintf(felog, "========== spid    : %s\n", hexstring(spid, sizeof(sgx_spid_t)));
    fprintf(felog, "========== nonce   : %s\n", hexstring(&nonce, sizeof(sgx_quote_nonce_t)));
    status = sgx_get_quote(&report,
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
        cprintf_err(felog, "sgx_get_quote: %08x\n", status);
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
        cprintf_err(felog, "Could not base64 encode quote\n");
        return false;
    }

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
    cprintf_info(felog, "Sending quote to on-chain node...\n");

    // Send quote to validation node, try out 3 times for network error.
    std::string req_data;
    std::string send_data;
    common_status_t common_status = CRUST_SUCCESS;
    send_data.append(b64quote);
    send_data.append(p_config->crust_address);
    sgx_ec256_signature_t send_data_sig;
    sgx_status_t sgx_status = ecall_sign_network_entry(global_eid, 
                                                       &common_status, 
                                                       send_data.c_str(), 
                                                       send_data.size(),
                                                       &send_data_sig);
    if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != common_status)
    {
        cprintf_err(felog, "Sign entry network data failed!\n");
        return false;
    }
    std::string signature_str(hexstring(&send_data_sig, sizeof(sgx_ec256_signature_t)));

    req_data.append("{ \"isvEnclaveQuote\": \"");
    req_data.append(b64quote).append("\", \"crust_address\": \"");
    req_data.append(p_config->crust_address).append("\", \"crust_account_id\": \"");
    req_data.append(p_config->crust_account_id.c_str()).append("\", \"signature\": \"");
    req_data.append(signature_str).append("\" }");
    int net_tryout = IAS_TRYOUT;

    httplib::Params params;
    params.emplace("arg", req_data);
    UrlEndPoint *urlendpoint = get_url_end_point(p_config->validator_api_base_url);
    httplib::Client *client = new httplib::Client(urlendpoint->ip, urlendpoint->port);
    client->set_timeout_sec(CLIENT_TIMEOUT);
    std::string path = urlendpoint->base + "/entry/network";
    std::shared_ptr<httplib::Response> res;
    while (net_tryout > 0)
    {
        res = client->Post(path.c_str(), params);
        if (!(res && res->status == 200))
        {
            cprintf_info(NULL, "Sending quote to verify failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
            sleep(3);
            net_tryout--;
            continue;
        }
        break;
    }

    if (!res || res->status != 200)
    {
        if (res)
        {
            cprintf_err(felog, "Entry network failed!Error code:%d\n", res->status);
        }
        else
        {
            cprintf_err(felog, "Entry network failed!Error: Get response failed!\n");
        }
        entry_status = false;
        goto cleanup;
    }

    g_entry_net_res = res->body;

cleanup:

    delete client;

    return entry_status;
}

/**
 * @description: waitting for the crust chain to run
 * @return: success or not
 * */
bool wait_chain_run_s(void)
{
    if (new_crust(p_config->crust_api_base_url, p_config->crust_password, p_config->crust_backup) == NULL)
    {
        cprintf_err(felog, "Init crust chain failed.\n");
        return false;
    }

    while (true)
    {
        if (get_crust()->is_online())
        {
            break;
        }
        else
        {
            cprintf_info(NULL, "Waitting for chain to run...\n");
            sleep(3);
        }
    }

    while (true)
    {
        BlockHeader *block_header = get_crust()->get_block_header();
        if (block_header->number > 0)
        {
            break;
        }
        else
        {
            cprintf_info(NULL, "Waitting for chain to run...\n");
            sleep(3);
        }
    }

    return true;
}

/**
 * @description: Check if there is enough height, send signed validation report to chain
 * */
void *do_upload_work_report_s(void *)
{
    while (true)
    {
        BlockHeader *block_header = get_crust()->get_block_header();
        if (block_header->number % BLOCK_HEIGHT == 0)
        {
            sleep(20);
            size_t report_len = 0;
            sgx_ec256_signature_t ecc_signature;
            validate_status_t validate_status = VALIDATION_SUCCESS;
            // Generate validation report and get report size
            if (ecall_generate_validation_report(global_eid, &report_len) != SGX_SUCCESS)
            {
                cprintf_err(felog, "Generate validation report failed!\n");
                continue;
            }

            // Get signed validation report
            char *report = (char *)malloc(report_len);
            memset(report, 0, report_len);
            if (ecall_get_signed_validation_report(global_eid, &validate_status,
                                                   block_header->hash.c_str(), block_header->number, &ecc_signature, report, report_len) != SGX_SUCCESS)
            {
                cprintf_err(felog, "Get signed validation report failed!\n");
            }
            else
            {
                if (validate_status != VALIDATION_SUCCESS)
                {
                    cprintf_info(felog, "Get signed validation report failed! Error code:%x\n", validate_status);
                }
                else
                {
                    // Send signed validation report to crust chain
                    json::JSON work_json = json::JSON::Load(std::string(report));
                    work_json["sig"] = hexstring((const uint8_t *)&ecc_signature, sizeof(ecc_signature));
                    work_json["block_height"] = block_header->number;
                    work_json["block_hash"] = block_header->hash;
                    std::string workStr = work_json.dump();
                    cprintf_info(felog, "Sign validation report successfully!\n%s\n", workStr.c_str());
                    // Delete space and line break
                    workStr.erase(std::remove(workStr.begin(), workStr.end(), ' '), workStr.end());
                    workStr.erase(std::remove(workStr.begin(), workStr.end(), '\n'), workStr.end());
                    if (!get_crust()->post_tee_work_report(workStr))
                    {
                        cprintf_err(felog, "Send work report to crust chain failed!\n");
                    }
                    else
                    {
                        cprintf_info(felog, "Send work report to crust chain successfully!\n");
                    }
                }
            }
            free(report);
        }
        else
        {
            cprintf_info(NULL, "Block height:%d is not enough!\n", block_header->number);
            sleep(3);
        }
    }
}

/**
 * @description: plot disk
 * @return: successed or failed
 */
bool do_plot_disk_s(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    cprintf_info(felog, "Start ploting disk...\n");
    // Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores
    #pragma omp parallel for
    for (size_t i = 0; i < p_config->empty_capacity; i++)
    {
        ecall_plot_disk(global_eid, p_config->empty_path.c_str());
    }

    // Generate empty root
    ret = ecall_generate_empty_root(global_eid);
    if (ret != SGX_SUCCESS)
    {
        cprintf_err(felog, "Generate empty root failed. Error code:%08x\n", 
                 ret);
        return false;
    }

    return true;
}

/**
 * @description: start parent worker
 */
void start(void)
{
    pid_t workerPID = getpid();
    pthread_t wthread;
    sgx_status_t sgx_status = SGX_SUCCESS;
    common_status_t common_status = CRUST_SUCCESS;
    cprintf_info(felog, "WorkerPID=%d\n", workerPID);
    cprintf_info(felog, "Worker global eid:%d\n", global_eid);

    /* Init conifigure */
    if (!initialize_config_s())
    {
        cprintf_err(felog, "Init configuration failed!\n");
        exit(INIT_CONFIG_ERROR);
    }

    /* Init related components */
    if (!initialize_components_s())
    {
        cprintf_err(felog, "Init component failed!\n");
        goto cleanup;
    }

    /* Init enclave */
    if (!initialize_enclave_s())
    {
        cprintf_err(felog, "Init enclave failed!\n");
        goto cleanup;
    }

    // TODO: New crust here which will be changed
    if (new_crust(p_config->crust_api_base_url, p_config->crust_password, p_config->crust_backup) == NULL)
    {
        cprintf_err(felog, "Init crust chain failed.\n");
        goto cleanup;
    }

    /* Restore data from file */
    if (SGX_SUCCESS != ecall_restore_enclave_data(global_eid, &common_status)
            || CRUST_SUCCESS != common_status)
    {
        cprintf_warn(felog, "Restore enclave data failed!Failed code:%lx\n", common_status);
        // If restore failed
        /* Generate ecc key pair */
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &sgx_status)
                || SGX_SUCCESS != sgx_status)
        {
            cprintf_err(felog, "Generate key pair failed!\n");
            goto cleanup;
        }
        cprintf_info(felog, "Generate key pair successfully!\n");
    
        /* Store crust info in enclave */
        common_status_t common_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != ecall_set_crust_account_id(global_eid, &common_status, p_config->crust_account_id.c_str(), 
                    p_config->crust_account_id.size())
                || CRUST_SUCCESS != common_status)
        {
            cprintf_err(felog, "Store backup information to enclave failed!Error code:%lx\n", common_status);
            goto cleanup;
        }

        /* Entry network */
        cprintf_info(felog, "Entrying network...\n");
        if (!entry_network_s())
        {
            goto cleanup;
        }
        cprintf_info(felog, "Entry network application successfully!Info:%s\n", g_entry_net_res.c_str());

        /* Plot empty disk */
        if (!do_plot_disk_s())
        {
            cprintf_err(felog, "Plot empty disk failed!\n");
            goto cleanup;
        }
        cprintf_info(felog, "Plot empty disk successfully!\n");

        /* Send identity to chain and send work report */
        if (!offline_chain_mode)
        {
            /* Send identity to crust chain */
            if (!wait_chain_run_s())
                goto cleanup;
            
            if (!get_crust()->post_tee_identity(g_entry_net_res))
            {
                cprintf_err(felog, "Send identity to crust chain failed!\n");
                goto cleanup;
            }
            cprintf_info(felog, "Send identity to crust chain successfully!\n");
        }
    }
    else
    {
        // Compare crust account it in configure file and recovered file
        if(SGX_SUCCESS != ecall_cmp_crust_account_id(global_eid, &common_status, 
                        p_config->crust_account_id.c_str(), p_config->crust_account_id.size())
                || CRUST_SUCCESS != common_status)
        {
            cprintf_err(felog, "Configure crust account id doesn't equal to recovered one!\n");
            goto cleanup;
        }
        cprintf_info(felog, "Restore enclave data successfully!\n");
    }


    if (!offline_chain_mode)
    {
        /* Send identity to crust chain */
        if (!wait_chain_run_s())
            goto cleanup;
            
        // Check block height and post report to chain
        if (pthread_create(&wthread, NULL, do_upload_work_report_s, NULL) != 0)
        {
            cprintf_err(felog, "Create checking block info thread failed!\n");
            goto cleanup;
        }
    }

    /* Main validate loop */
    ecall_main_loop(global_eid, p_config->empty_path.c_str(), p_config->recover_file_path.c_str());


cleanup:
    /* End and release */
    delete p_config;
    if (get_ipfs() != NULL)
        delete get_ipfs();

    if (p_api_handler != NULL)
        delete p_api_handler;

    if (global_eid != 0)
        sgx_destroy_enclave(global_eid);

    if (felog != NULL)
        close_logfile(felog);

    exit(-1);
}

/**
 * @desination: Main function to start application
 * @return: Start status
 * */
int single_process_run()
{
    // Create log file
    if (felog == NULL)
        felog = create_logfile(LOG_FILE_PATH);

    start();

    return 1;
}
