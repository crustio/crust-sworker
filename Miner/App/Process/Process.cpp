#include "Process.h"
#include "DataBase.h"

#define RECEIVE_PID_RETRY 30

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid;
// Pointor to configure instance
Config *p_config = NULL;
// Pointer to http handler instance
ApiHandler *p_api_handler = NULL;

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
    /* Create base path */
    create_directory(p_config->empty_path);

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

    /* Initialize DataBase */
    if (DataBase::get_instance() == NULL)
    {
        p_log->err("Initialize DataBase failed!\n");
        return false;
    }

    p_log->info("Init components successfully!\n");

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
        if (block_header->number % REPORT_BLOCK_HEIGHT_BASE == 0)
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
                else if (crust_status == CRUST_BLOCK_HEIGHT_EXPIRED)
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
    std::string tee_identity_result = "";
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
    if (SGX_SUCCESS != ecall_restore_metadata(global_eid, &crust_status) || CRUST_SUCCESS != crust_status)
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
            if (!entry_network(p_config, tee_identity_result))
            {
                goto cleanup;
            }
            p_log->info("Entry network application successfully! TEE identity: %s\n", tee_identity_result.c_str());
            
            /* Send identity to crust chain */
            if (!crust::Chain::get_instance()->wait_for_running())
            {
                goto cleanup;
            }

            if (!crust::Chain::get_instance()->post_tee_identity(tee_identity_result))
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
        // Check block height and post report to chain
        if (pthread_create(&wthread, NULL, do_upload_work_report, NULL) != 0)
        {
            p_log->err("Create checking block info thread failed!\n");
            goto cleanup;
        }
    }

    /* Main validate loop */
    ecall_main_loop(global_eid, p_config->empty_path.c_str());

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
