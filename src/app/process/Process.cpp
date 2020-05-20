#include "Process.h"
#include "DataBase.h"
#include "WebServer.h"

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
 * @description: initialize the components:
 *   config -> user configurations and const configurations
 *   ipfs -> used to store meaningful files, please make sure ipfs is running before running daemon
 *   api handler -> external API interface 
 * @return: success or failure
 */
bool initialize_components(void)
{
    // Create base path
    create_directory(p_config->empty_path);

    // IPFS component
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

    // Init crust
    if (crust::Chain::get_instance() == NULL)
    {
        p_log->err("Init crust chain failed!\n");
        return false;
    }

    // Start http service
    pthread_t wthread;
    if (pthread_create(&wthread, NULL, start_webservice, NULL) != 0)
    {
        return false;
    }

    // Initialize DataBase
    if (crust::DataBase::get_instance() == NULL)
    {
        p_log->err("Initialize DataBase failed!\n");
        return false;
    }

    p_log->info("Init components successfully!\n");

    return true;
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
 * @desination: Main function to start application
 * @return: Start status
 * */
int process_run()
{
    pid_t worker_pid = getpid();
    pthread_t wthread;
    pthread_t srd_empty_disk_thread;
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    std::string tee_identity_result = "";
    int return_status = 1;
    p_log->info("WorkerPID = %d\n", worker_pid);
    p_log->info("Worker global eid: %d\n", global_eid);

    // Init conifigure
    if (!initialize_config())
    {
        p_log->err("Init configuration failed!\n");
        return_status = -1;
        goto cleanup;
    }

    // Init related components
    if (!initialize_components())
    {
        p_log->err("Init component failed!\n");
        return_status = -1;
        goto cleanup;
    }

    // Init enclave
    if (!initialize_enclave())
    {
        p_log->err("Init enclave failed!\n");
        return_status = -1;
        goto cleanup;
    }

    // ----- Restore data from file ----- //
    if (SGX_SUCCESS != ecall_restore_metadata(global_eid, &crust_status) || CRUST_SUCCESS != crust_status)
    {
        // Restore data failed
        p_log->warn("Restore enclave data failed!Failed code:%lx\n", crust_status);
        // Generate ecc key pair
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &sgx_status) || SGX_SUCCESS != sgx_status)
        {
            p_log->err("Generate key pair failed!\n");
            return_status = -1;
            goto cleanup;
        }
        p_log->info("Generate key pair successfully!\n");

        // Store crust info in enclave
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != ecall_set_chain_account_id(global_eid, &crust_status,
                p_config->chain_account_id.c_str(), p_config->chain_account_id.size()) ||
            CRUST_SUCCESS != crust_status)
        {
            p_log->err("Store backup information to enclave failed!Error code:%lx\n", crust_status);
            return_status = -1;
            goto cleanup;
        }

        // Srd empty disk
        if (pthread_create(&srd_empty_disk_thread, NULL, do_srd_empty_disk, NULL) != 0)
        {
            p_log->err("Create srd empty disk thread failed!\n");
            return_status = -1;
            goto cleanup;
        }

        // Send identity to chain and send work report
        if (!offline_chain_mode)
        {
            // Entry network
            p_log->info("Entrying network...\n");
            if (!entry_network(p_config, tee_identity_result))
            {
                goto cleanup;
                return_status = -1;
            }
            p_log->info("Entry network application successfully! TEE identity: %s\n", tee_identity_result.c_str());

            // Send identity to crust chain
            if (!crust::Chain::get_instance()->wait_for_running())
            {
                return_status = -1;
                goto cleanup;
            }

            if (!crust::Chain::get_instance()->post_tee_identity(tee_identity_result))
            {
                p_log->err("Send identity to crust chain failed!\n");
                return_status = -1;
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
            return_status = -1;
            goto cleanup;
        }
        p_log->info("Restore enclave data successfully!\n");
    }

    if (!offline_chain_mode)
    {
        // Check block height and post report to chain
        if (pthread_create(&wthread, NULL, work_report_loop, NULL) != 0)
        {
            p_log->err("Create checking block info thread failed!\n");
            return_status = -1;
            goto cleanup;
        }
    }

    // Main validate loop
    ecall_main_loop(global_eid, p_config->empty_path.c_str());

cleanup:
    // End and release
    delete p_config;
    if (get_ipfs() != NULL)
        delete get_ipfs();

    if (p_api_handler != NULL)
        delete p_api_handler;

    if (global_eid != 0)
        sgx_destroy_enclave(global_eid);

    return return_status;
}
