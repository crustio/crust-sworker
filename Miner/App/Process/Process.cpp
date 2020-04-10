#include "Process.h"

#define RECEIVE_PID_RETRY 30

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

crust::Log *p_log = crust::Log::get_instance();
extern bool offline_chain_mode;
extern bool in_changing_empty;
extern std::mutex change_empty_mutex;

/**
 * @description: Init configuration
 * @return: Init status
 * */
bool initialize_config(void)
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
bool initialize_enclave()
{
    int sgx_support;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Can we run SGX? */
    p_log->info("Initial enclave...\n");
    sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO)
    {
        p_log->err("This system does not support Intel SGX.\n");
        return -1;
    }
    else
    {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
        {
            p_log->err("Intel SGX is supported on this system but disabled in the BIOS\n");
            return -1;
        }
        else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
        {
            p_log->err("Intel SGX will be enabled after the next reboot\n");
            return -1;
        }
        else if (!(sgx_support & SGX_SUPPORT_ENABLED))
        {
            p_log->err("Intel SGX is supported on this sytem but not available for use. \
                    The system may lock BIOS support, or the Platform Software is not available\n");
            return -1;
        }
    }

    /* Launch the enclave */
    ret = sgx_create_enclave(ENCLAVE_FILE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        p_log->err("Init enclave failed.Error code:%08x\n", ret);
        return false;
    }

    /* Generate code measurement */
    if (SGX_SUCCESS != ecall_gen_sgx_measurement(global_eid, &ret))
    {
        p_log->err("Generate code measurement failed!error code:%08x\n", ret);
        return false;
    }

    p_log->info("Initial enclave successfully!Enclave id:%d\n", global_eid);

    return true;
}

/**
 * @description: Start http service
 * */
void *start_http(void *)
{
    /* API handler component */
    p_log->info("Initing api url:%s...\n", p_config->api_base_url.c_str());
    p_api_handler = new ApiHandler(&global_eid);
    if (p_api_handler == NULL)
    {
        p_log->err("Init api handler failed.\n");
        return NULL;
    }
    //p_log->info("Init api handler successfully.\n");
    p_api_handler->start();
    p_log->err("Start network service failed!\n");
    return NULL;
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
    if (new_ipfs(p_config->ipfs_api_base_url.c_str()) == NULL)
    {
        p_log->err("Init ipfs failed.\n");
        return false;
    }

    if (!get_ipfs()->is_online())
    {
        p_log->err("ipfs daemon is not started up! Please start it up!\n");
        return false;
    }

    /* Init crust */
    if (crust::Chain::get_instance() == NULL)
    {
        p_log->err("Init crust chain failed!\n");
        return false;
    }

    /* Start http service */
    pthread_t wthread;
    if (pthread_create(&wthread, NULL, start_http, NULL) != 0)
    {
        p_log->err("Create rest service thread failed!\n");
        return false;
    }
    p_log->info("Start rest service successfully!\n");

    p_log->info("Init components successfully!\n");

    return true;
}

/*
 * @description: entry network off-chain node sends quote to onchain node
 *   to verify identity
 * @return: success or failure
 * */
bool entry_network()
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
    int common_tryout = 3;

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
            p_log->err("Nonce: RDRAND underflow\n");
            return false;
        }
    }

    if (OPT_ISSET(flags, OPT_LINK))
    {
        linkable = SGX_LINKABLE_SIGNATURE;
    }

    /* Get SGX quote */
    memset(&report, 0, sizeof(report));

    status = sgx_init_quote(&target_info, &epid_gid);
    int tryout = 1;
    do
    {
        if (SGX_SUCCESS == status)
            break;

        if (SGX_ERROR_BUSY == status)
        {
            if (tryout > common_tryout)
            {
                p_log->err("Initialize sgx quote tryout!\n");
                return false;
            }
            p_log->info("SGX device is busy, trying again(%d time)...\n", tryout);
            tryout++;
            sleep(1);
        }
        else
        {
            p_log->err("SGX init quote failed!Error code: %08x\n", status);
            return false;
        }
    } while (true);

    status = ecall_get_report(global_eid, &sgxrv, &report, &target_info);
    if (status != SGX_SUCCESS)
    {
        p_log->err("get_report: %08x\n", status);
        return false;
    }
    if (sgxrv != SGX_SUCCESS)
    {
        p_log->err("sgx_create_report: %08x\n", sgxrv);
        return false;
    }

    // sgx_get_quote_size() has been deprecated, but SGX PSW may be too old
    // so use a wrapper function.
    if (!get_quote_size(&status, &sz))
    {
        p_log->err("PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return false;
    }
    if (status != SGX_SUCCESS)
    {
        p_log->err("SGX error while getting quote size: %08x\n", status);
        return false;
    }

    quote = (sgx_quote_t *)malloc(sz);
    if (quote == NULL)
    {
        p_log->err("out of memory\n");
        return false;
    }

    memset(quote, 0, sz);
    p_log->debug("========== linkable: %d\n", linkable);
    p_log->debug("========== spid    : %s\n", hexstring(spid, sizeof(sgx_spid_t)));
    p_log->debug("========== nonce   : %s\n", hexstring(&nonce, sizeof(sgx_quote_nonce_t)));
    status = sgx_get_quote(&report, linkable,
            spid, &nonce, NULL, 0, &qe_report, quote, sz);
    if (status != SGX_SUCCESS)
    {
        p_log->err("sgx_get_quote: %08x\n", status);
        return false;
    }

    /* Print SGX quote */
    p_log->debug("quote report_data: %s\n", hexstring((const void *)(quote->report_body.report_data.d), sizeof(quote->report_body.report_data.d)));
    p_log->debug("ias quote report version :%d\n", quote->version);
    p_log->debug("ias quote report signtype:%d\n", quote->sign_type);
    p_log->debug("ias quote report epid    :%d\n", *quote->epid_group_id);
    p_log->debug("ias quote report qe svn  :%d\n", quote->qe_svn);
    p_log->debug("ias quote report pce svn :%d\n", quote->pce_svn);
    p_log->debug("ias quote report xeid    :%d\n", quote->xeid);
    p_log->debug("ias quote report basename:%s\n", hexstring(quote->basename.name, 32));
    p_log->debug("ias quote mr enclave     :%s\n", hexstring(&quote->report_body.mr_enclave, 32));

    // Get base64 quote
    b64quote = base64_encode((char *)quote, sz);
    if (b64quote == NULL)
    {
        p_log->err("Could not base64 encode quote\n");
        return false;
    }

    p_log->debug("{\n");
    p_log->debug("\"isvEnclaveQuote\":\"%s\"", b64quote);
    if (OPT_ISSET(flags, OPT_NONCE))
    {
        p_log->debug(",\n\"nonce\":\"");
        print_hexstring(&nonce, 16);
        p_log->debug("\"");
    }

    if (OPT_ISSET(flags, OPT_PSE))
    {
        p_log->debug(",\n\"pseManifest\":\"%s\"", b64manifest);
    }
    p_log->debug("\n}\n");

    /* Send quote to validation node */
    p_log->info("Sending quote to on-chain node...\n");

    // Send quote to validation node, try out 3 times for network error.
    std::string req_data;
    std::string send_data;
    crust_status_t crust_status = CRUST_SUCCESS;
    send_data.append(b64quote);
    send_data.append(p_config->chain_address);
    sgx_ec256_signature_t send_data_sig;
    sgx_status_t sgx_status = ecall_sign_network_entry(global_eid, &crust_status, 
            send_data.c_str(), send_data.size(), &send_data_sig);
    if (SGX_SUCCESS != sgx_status || CRUST_SUCCESS != crust_status)
    {
        p_log->err("Sign entry network data failed!\n");
        return false;
    }
    std::string signature_str(hexstring(&send_data_sig, sizeof(sgx_ec256_signature_t)));

    req_data.append("{ \"isvEnclaveQuote\": \"");
    req_data.append(b64quote).append("\", \"chain_address\": \"");
    req_data.append(p_config->chain_address).append("\", \"chain_account_id\": \"");
    req_data.append(p_config->chain_account_id.c_str()).append("\", \"signature\": \"");
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
            p_log->info("Sending quote to verify failed! Trying again...(%d)\n", IAS_TRYOUT - net_tryout + 1);
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
            p_log->err("Entry network failed!Error code:%d\n", res->status);
        }
        else
        {
            p_log->err("Entry network failed!Error: Get response failed!\n");
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
bool wait_chain_run(void)
{
    crust::Chain* p_chain = crust::Chain::get_instance();
    if (p_chain == NULL)
    {
        p_log->err("Init crust chain failed.\n");
        return false;
    }

    while (true)
    {
        if (p_chain->is_online())
        {
            break;
        }
        else
        {
            p_log->info("Waitting for chain to run...\n");
            sleep(3);
        }
    }

    while (true)
    {
        crust::BlockHeader *block_header = p_chain->get_block_header();
        if (block_header->number > 0)
        {
            break;
        }
        else
        {
            p_log->info("Waitting for chain to run...\n");
            sleep(3);
        }
    }

    return true;
}

/**
 * @description: Check if there is enough height, send signed validation report to chain
 * */
void *do_upload_work_report(void *)
{
    size_t report_len = 0;
    sgx_ec256_signature_t ecc_signature;
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::Chain* p_chain = crust::Chain::get_instance();

    while (true)
    {
        crust::BlockHeader *block_header = p_chain->get_block_header();
        if (block_header->number % BLOCK_HEIGHT == 0)
        {
            sleep(20);
            // Generate validation report and get report size
            if (ecall_generate_validation_report(global_eid, &report_len) != SGX_SUCCESS)
            {
                p_log->err("Generate validation report failed!\n");
                continue;
            }

            // Get signed validation report
            char *report = (char *)malloc(report_len);
            memset(report, 0, report_len);
            if (SGX_SUCCESS != ecall_get_signed_validation_report(global_eid, &crust_status,
                        block_header->hash.c_str(), block_header->number, &ecc_signature, report, report_len))
            {
                p_log->err("Get signed validation report failed!\n");
            }
            else
            {
                if (crust_status == CRUST_SUCCESS)
                {
                    // Send signed validation report to crust chain
                    json::JSON work_json = json::JSON::Load(std::string(report));
                    work_json["sig"] = hexstring((const uint8_t *)&ecc_signature, sizeof(ecc_signature));
                    work_json["block_height"] = block_header->number;
                    work_json["block_hash"] = block_header->hash;
                    std::string workStr = work_json.dump();
                    p_log->info("Sign validation report successfully!\n%s\n", workStr.c_str());
                    // Delete space and line break
                    workStr.erase(std::remove(workStr.begin(), workStr.end(), ' '), workStr.end());
                    workStr.erase(std::remove(workStr.begin(), workStr.end(), '\n'), workStr.end());
                    if (!p_chain->post_tee_work_report(workStr))
                    {
                        p_log->err("Send work report to crust chain failed!\n");
                    }
                    else
                    {
                        p_log->info("Send work report to crust chain successfully!\n");
                    }
                }
                if (crust_status == CRUST_BLOCK_HEIGHT_EXPIRED)
                {
                    p_log->info("Block height expired.\n");
                }
                else
                {
                    p_log->err("Get signed validation report failed! Error code:%x\n", crust_status);
                }
            }
            free(report);
        }
        else
        {
            p_log->info("Block height:%d is not enough!\n", block_header->number);
            sleep(3);
        }
    }
}

/**
 * @description: seal random data to fill disk
 * @return: successed or failed
 */
void *do_srd_empty_disk(void *)
{
    change_empty_mutex.lock();
    in_changing_empty = true;
    change_empty_mutex.unlock();

    create_directory(p_config->empty_path);
    size_t free_space = get_free_space_under_directory(p_config->empty_path) / 1024;
    p_log->info("Free space is %luG disk in '%s'\n", free_space, p_config->empty_path.c_str());
    size_t true_srd_capacity = free_space <= 10 ? 0 : std::min(free_space - 10, p_config->empty_capacity);
    p_log->info("Start sealing %luG empty files (thread number: %d) ...\n", true_srd_capacity, p_config->srd_thread_num);
    // Use omp parallel to seal empty disk, the number of threads is equal to the number of CPU cores
    #pragma omp parallel for num_threads(p_config->srd_thread_num)
    for (size_t i = 0; i < true_srd_capacity; i++)
    {
        ecall_srd_increase_empty(global_eid, p_config->empty_path.c_str());
    }

    change_empty_mutex.lock();
    in_changing_empty = false;
    change_empty_mutex.unlock();

    p_log->info("Seal %luG random data successed.\n", true_srd_capacity);
    return NULL;
}

/**
 * @description: start parent worker
 */
void start(void)
{
    pid_t workerPID = getpid();
    pthread_t wthread;
    pthread_t srd_empty_disk_thread;
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    p_log->info("WorkerPID=%d\n", workerPID);
    p_log->info("Worker global eid:%d\n", global_eid);

    /* Init conifigure */
    if (!initialize_config())
    {
        p_log->err("Init configuration failed!\n");
        goto cleanup;
    }

    /* Init related components */
    if (!initialize_components())
    {
        p_log->err("Init component failed!\n");
        goto cleanup;
    }

    /* Init enclave */
    if (!initialize_enclave())
    {
        p_log->err("Init enclave failed!\n");
        goto cleanup;
    }

    /* Restore data from file */
    if (SGX_SUCCESS != ecall_restore_enclave_data(global_eid, &crust_status, p_config->recover_file_path.c_str()) || CRUST_SUCCESS != crust_status)
    {
        // Restore data failed
        p_log->warn("Restore enclave data failed!Failed code:%lx\n", crust_status);
        /* Generate ecc key pair */
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &sgx_status) || SGX_SUCCESS != sgx_status)
        {
            p_log->err("Generate key pair failed!\n");
            goto cleanup;
        }
        p_log->info("Generate key pair successfully!\n");

        /* Store crust info in enclave */
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != ecall_set_chain_account_id(global_eid, &crust_status, 
                    p_config->chain_account_id.c_str(), p_config->chain_account_id.size())
                || CRUST_SUCCESS != crust_status)
        {
            p_log->err("Store backup information to enclave failed!Error code:%lx\n", crust_status);
            goto cleanup;
        }

        /* Srd empty disk */
        if (pthread_create(&srd_empty_disk_thread, NULL, do_srd_empty_disk, NULL) != 0)
        {
            p_log->err("Create srd empty disk thread failed!\n");
            goto cleanup;
        }

        /* Send identity to chain and send work report */
        if (!offline_chain_mode)
        {
            /* Entry network */
            p_log->info("Entrying network...\n");
            if (!entry_network())
            {
                goto cleanup;
            }
            p_log->info("Entry network application successfully!Info:%s\n", g_entry_net_res.c_str());
            
            /* Send identity to crust chain */
            if (!wait_chain_run())
            {
                goto cleanup;
            }

            if (!crust::Chain::get_instance()->post_tee_identity(g_entry_net_res))
            {
                p_log->err("Send identity to crust chain failed!\n");
                goto cleanup;
            }
            p_log->info("Send identity to crust chain successfully!\n");
        }
    }
    else
    {
        // Compare crust account it in configure file and recovered file
        if (SGX_SUCCESS != ecall_cmp_chain_account_id(global_eid, &crust_status,
                                                      p_config->chain_account_id.c_str(), p_config->chain_account_id.size()) ||
            CRUST_SUCCESS != crust_status)
        {
            p_log->err("Configure chain account id doesn't equal to recovered one!\n");
            goto cleanup;
        }
        p_log->info("Restore enclave data successfully!\n");
    }

    if (!offline_chain_mode)
    {
        /* Send identity to crust chain */
        if (!wait_chain_run())
        {
            goto cleanup;
        }
        
        // Check block height and post report to chain
        if (pthread_create(&wthread, NULL, do_upload_work_report, NULL) != 0)
        {
            p_log->err("Create checking block info thread failed!\n");
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

    exit(-1);
}

/**
 * @desination: Main function to start application
 * @return: Start status
 * */
int process_run()
{
    start();
    return 1;
}
