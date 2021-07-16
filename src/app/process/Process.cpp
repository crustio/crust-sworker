#include "Process.h"
#include "WebServer.h"

bool upgrade_try_start();
bool upgrade_try_restore();
void upgrade_try_complete(bool success);

bool start_task(task_func_t func);
bool restore_tasks();

// Global EID shared by multiple threads
sgx_enclave_id_t global_eid = 0;
// Pointor to configure instance
Config *p_config = NULL;
// Map to record specific task
std::map<task_func_t, std::shared_ptr<std::future<void>>> g_tasks_m;

crust::Log *p_log = crust::Log::get_instance();
extern int g_start_server_success;
extern bool g_upgrade_flag;
extern bool offline_chain_mode;

/**
 * @description: Init configuration
 * @return: Init status
 */
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
 * @description: Call sgx_create_enclave to initialize an enclave instance
 * @return: Success or failure
 */
bool initialize_enclave()
{
    int sgx_support;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // ----- Can we run SGX? ----- //
    p_log->info("Initial enclave...\n");
    sgx_support = get_sgx_support();
    if (sgx_support & SGX_SUPPORT_NO)
    {
        p_log->err("This system does not support Intel SGX.\n");
        return false;
    }
    else
    {
        if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
        {
            p_log->err("Intel SGX is supported on this system but disabled in the BIOS\n");
            return false;
        }
        else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
        {
            p_log->err("Intel SGX will be enabled after the next reboot\n");
            return false;
        }
        else if (!(sgx_support & SGX_SUPPORT_ENABLED))
        {
            p_log->err("Intel SGX is supported on this sytem but not available for use. "
                    "The system may lock BIOS support, or the Platform Software is not available\n");
            return false;
        }
    }
    p_log->debug("Your machine can support SGX.\n");

    // ----- Launch the enclave ----- //
    uint8_t *p_wl_data = NULL;
    size_t wl_data_size = 0;
    if (CRUST_SUCCESS == get_file(SGX_WL_FILE_PATH, &p_wl_data, &wl_data_size))
    {
        sgx_status_t reg_ret = sgx_register_wl_cert_chain(p_wl_data, wl_data_size);
        if (SGX_SUCCESS != reg_ret)
        {
            p_log->warn("Encounter problem when registering local white list cert, code:%lx.\n", reg_ret);
        }
        free(p_wl_data);
    }
    ret = sgx_create_enclave(ENCLAVE_FILE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        switch (ret)
        {
            case SGX_ERROR_NO_DEVICE:
                p_log->err("Init enclave failed. Open sgx driver failed, please uninstall your sgx "
                        "driver (OOT driver and DCAP driver) and reinstall it (OOT driver). "
                        "If it still fails, please try to reinstall the system. Error code:%lx\n", ret);
                break;
            default:
                p_log->err("Init enclave failed.Error code:%lx\n", ret);

        }
        return false;
    }
    p_log->info("Initial enclave successfully!Enclave id:%d\n", global_eid);

    // ----- Generate code measurement ----- //
    if (SGX_SUCCESS != Ecall_gen_sgx_measurement(global_eid, &ret))
    {
        p_log->err("Generate code measurement failed!error code:%lx\n", ret);
        return false;
    }
    p_log->debug("Generate code measurement successfully!\n");

    return true;
}

/**
 * @description: Initialize the components:
 *   config -> user configurations and const configurations
 *   api handler -> external API interface 
 * @return: Success or failure
 */
bool initialize_components(void)
{
    // Create path
    if (CRUST_SUCCESS != create_directory(p_config->base_path))
    {
        p_log->err("Create base path failed!!\n");
        return false;
    }

    // Init crust
    if (crust::Chain::get_instance() == NULL)
    {
        p_log->err("Init crust chain failed!\n");
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
 * @description: Inform old version to start upgrade
 * @return: Inform result
 */
bool upgrade_try_start()
{
    std::shared_ptr<HttpClient> client(new HttpClient());
    ApiHeaders headers = {{"backup",p_config->chain_backup}};
    p_log->info("Informing old version to get ready for upgrade...\n");
    int start_wait_time = 16;
    std::string err_msg;
    while (true)
    {
        http::response<http::string_body> res_inform = client->Get(p_config->base_url + "/upgrade/start", "", headers);
        if ((int)res_inform.result() != 200)
        {
            if ((int)res_inform.result() == 404)
            {
                p_log->err("Please make sure old sWorker is running!Error code:%d\n", res_inform.result());
                return false;
            }
            if (res_inform.body().compare(err_msg) != 0)
            {
                p_log->info("Old version not ready for upgrade!Message:%s, status:%d, try again...\n", res_inform.body().c_str(), res_inform.result());
                err_msg = res_inform.body();
            }
            sleep(start_wait_time);
            continue;
        }

        p_log->info("Inform old version to upgrade successfully!\n");
        break;
    }

    return true;
}

/**
 * @description: Restore upgrade data
 * @return: Restore result
 */
bool upgrade_try_restore()
{
    std::shared_ptr<HttpClient> client(new HttpClient());
    ApiHeaders headers = {{"backup",p_config->chain_backup}};
    p_log->info("Waiting for upgrade data...\n");
    int restore_tryout = 3;
    int meta_wait_time = 3;
    http::response<http::string_body> res_meta;
    sgx_status_t sgx_status = SGX_SUCCESS;
    std::string err_msg;
    while (true)
    {
        // Try to get metadata
        res_meta = client->Get(p_config->base_url + "/upgrade/metadata", "", headers);
        if ((int)res_meta.result() != 200)
        {
            if ((int)res_meta.result() == 404)
            {
                p_log->err("Get upgrade data failed!Old sWorker is not running!\n");
                return false;
            }
            if (res_meta.body().compare(err_msg) != 0)
            {
                p_log->info("Old version Message:%s\n", res_meta.body().c_str());
                err_msg = res_meta.body();
            }
            sleep(meta_wait_time);
            continue;
        }
        p_log->info("Get upgrade data successfully!Data size:%ld.\n", res_meta.body().size());
        break;
    }

restore_try_again:
    // Init enclave
    if (!initialize_enclave())
    {
        p_log->err("Init enclave failed!\n");
        return false;
    }

    // Generate ecc key pair
    if (SGX_SUCCESS != Ecall_gen_key_pair(global_eid, &sgx_status, p_config->chain_account_id.c_str(), p_config->chain_account_id.size())
            || SGX_SUCCESS != sgx_status)
    {
        p_log->err("Generate key pair failed!\n");
        return false;
    }
    p_log->info("Generate key pair successfully!\n");

    // Restore workload and report old version's work report
    crust_status_t crust_status = CRUST_SUCCESS;
    size_t meta_size = res_meta.body().size();
    const char *p_meta = res_meta.body().c_str();
    sgx_status = safe_ecall_store2(global_eid, &crust_status, ECALL_RESTORE_FROM_UPGRADE, reinterpret_cast<const uint8_t *>(p_meta), meta_size);
    if (SGX_SUCCESS != sgx_status)
    {
        p_log->err("Invoke SGX API failed!Error code:%lx.\n", sgx_status);
        return false;
    }
    if (CRUST_SUCCESS != crust_status)
    {
        if (CRUST_INIT_QUOTE_FAILED == crust_status)
        {
            if (--restore_tryout > 0)
            {
                sgx_destroy_enclave(global_eid);
                sleep(60);
                goto restore_try_again;
            }
        }
        p_log->err("Restore workload from upgrade data failed!Error code:%lx.\n", crust_status);
        return false;
    }
    p_log->info("Restore workload from upgrade data successfully!\n");

    return true;
}

/**
 * @description: Inform old version upgrade result
 * @param success -> Upgrade result
 */
void upgrade_try_complete(bool success)
{
    std::shared_ptr<HttpClient> client(new HttpClient());
    ApiHeaders headers = {{"backup",p_config->chain_backup}};
    p_log->info("Informing old version upgrade is successful...\n");
    json::JSON upgrade_ret;
    upgrade_ret["success"] = success;
    int complete_wait_time = 1;
    while (true)
    {
        // Inform old version to close
        http::response<http::string_body> res_complete = client->Get(p_config->base_url + "/upgrade/complete", upgrade_ret.dump(), headers);
        if ((int)res_complete.result() != 200 && (int)res_complete.result() != 404)
        {
            p_log->warn("Inform old version failed!Message:%s, try again...\n", res_complete.body().c_str());
            sleep(complete_wait_time);
            continue;
        }
        break;
    }
    p_log->info("Inform old version upgrade %s!\n", success ? "successfully" : "failed");
    if (!success)
    {
        print_logo(UPGRADE_FAILED_LOGO, HRED);
        return;
    }

    // Init related components
    p_log->info("Waiting for old version's webservice stop...\n");
    // Waiting old version stop
    long check_old_api_tryout = 0;
    while (true)
    {
        // Inform old version to close
        http::response<http::string_body> res_test = client->Get(p_config->base_url + "/enclave/thread_info", "", headers);
        if ((int)res_test.result() == 404)
        {
            break;
        }
        if (check_old_api_tryout % 10 == 0)
        {
            p_log->info("Old version webservice is still working, please wait...\n");
        }
        check_old_api_tryout++;
        sleep(3);
    }
    sleep(10);
    UrlEndPoint urlendpoint = get_url_end_point(p_config->base_url);
    while (!initialize_components())
    {
        p_log->err("Please check if port:%d has been used. If it is being used, stop related process!\n", urlendpoint.port);
        sleep(10);
    }

    print_logo(UPGRADE_SUCCESS_LOGO, HGREEN);
}

/**
 * @description: Check if upgrade, this function executes until upgrade successfully
 */
void do_upgrade()
{
    while (true)
    {
        if (!upgrade_try_start())
        {
            sleep(30);
            continue;
        }

        bool res = upgrade_try_restore();

        upgrade_try_complete(res);

        if (res)
        {
            break;
        }

        sleep(30);
    }
}

/**
 * @description: Wrapper for main loop
 */
void main_loop(void)
{
    Ecall_main_loop(global_eid);
}

/**
 * @description: Start task by name
 * @param func -> Task function indicator
 * @return: Start result
 */
bool start_task(task_func_t func)
{
    // Check if service is started
    if (g_tasks_m.find(func) != g_tasks_m.end())
    {
        if (g_tasks_m[func]->wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        {
            return true;
        }
    }

    // Start service
    g_tasks_m[func] = std::make_shared<std::future<void>>(std::async(std::launch::async, func));
    if (func == start_webservice)
    {
        while (g_start_server_success == -1)
        {
            sleep(0.01);
        }
        if (g_start_server_success == 0)
        {
            return false;
        }
        g_start_server_success = -1;
    }

    return true;
}

/**
 * @description: Restore tasks
 * @return: Restore result
 */
bool restore_tasks()
{
    for (auto it = g_tasks_m.begin(); it != g_tasks_m.end(); it++)
    {
        if (it->second->wait_for(std::chrono::seconds(0)) == std::future_status::ready)
        {
            if (!start_task(it->first))
            {
                return false;
            }
        }
    }

    return true;
}

/**
 * @description: Main function to start application
 * @return: Start status
 */
int process_run()
{
    pid_t worker_pid = getpid();
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    int return_status = 1;
    int check_interval = 15;
    int upgrade_timeout = 3 * REPORT_SLOT * BLOCK_INTERVAL;
    int upgrade_tryout = upgrade_timeout / check_interval;
    int entry_tryout = 3;
    size_t srd_task = 0;
    long srd_real_change = 0;
    std::string srd_task_str;
    EnclaveData *ed = EnclaveData::get_instance();
    crust::DataBase *db = NULL;
    bool is_restart = false;
    p_log->info("WorkerPID = %d\n", worker_pid);

    // Init conifigure
    if (!initialize_config())
    {
        p_log->err("Init configuration failed!\n");
        return_status = -1;
        goto cleanup;
    }

    // Construct uuid to disk path map
    ed->construct_uuid_disk_path_map();

    // There are three startup mode: upgrade, restore and normal
    // Upgrade mode will communicate with old version for data transferring.
    // Resotre mode will restore enclave data from database.
    // Normal mode will start up a new enclave.
    // ----- Upgrade mode ----- //
    if (g_upgrade_flag)
    {
        // Check and do upgrade
        do_upgrade();
        p_log->info("Upgrade from old version successfully!\n");
    }
    else
    {
        // Init related components
        if (!initialize_components())
        {
            p_log->err("Init component failed!\n");
            return_status = -1;
            goto cleanup;
        }

entry_network_flag:
        // Init enclave
        if (!initialize_enclave())
        {
            p_log->err("Init enclave failed!\n");
            return_status = -1;
            goto cleanup;
        }
        p_log->info("Worker global eid: %d\n", global_eid);

        // Start enclave
        if (SGX_SUCCESS != Ecall_restore_metadata(global_eid, &crust_status) || CRUST_SUCCESS != crust_status)
        {
            // ----- Normal startup ----- //
            // Restore data failed
            p_log->info("Starting a new enclave...(restore code:%lx)\n", crust_status);

            // Generate ecc key pair
            if (SGX_SUCCESS != Ecall_gen_key_pair(global_eid, &sgx_status, p_config->chain_account_id.c_str(), p_config->chain_account_id.size())
                    || SGX_SUCCESS != sgx_status)
            {
                p_log->err("Generate key pair failed!\n");
                return_status = -1;
                goto cleanup;
            }
            p_log->info("Generate key pair successfully!\n");

            // Start http service
            if (!start_task(start_webservice))
            {
                p_log->err("Start web service failed!\n");
                goto cleanup;
            }

            // Entry network
            if (!offline_chain_mode)
            {
                crust_status = entry_network();
                if (CRUST_SUCCESS != crust_status)
                {
                    if (CRUST_INIT_QUOTE_FAILED == crust_status && entry_tryout > 0)
                    {
                        entry_tryout--;
                        sgx_destroy_enclave(global_eid);
                        global_eid = 0;
                        sleep(60);
                        goto entry_network_flag;
                    }
                    goto cleanup;
                    return_status = -1;
                }
            }
            else
            {
                p_log->info("Enclave id info:\n%s\n", ed->get_enclave_id_info().c_str());
            }

            // Set init srd capacity
            srd_task = 1;
        }
        else
        {
            // ----- Restore data successfully ----- //
            // Compare crust account it in configure file and recovered file
            if (SGX_SUCCESS != Ecall_cmp_chain_account_id(global_eid, &crust_status,
                    p_config->chain_account_id.c_str(), p_config->chain_account_id.size())
                || CRUST_SUCCESS != crust_status)
            {
                p_log->err("Configure chain account id doesn't equal to recovered one!\n");
                return_status = -1;
                goto cleanup;
            }

            // Wait for chain running
            if (!crust::Chain::get_instance()->wait_for_running())
            {
                p_log->err("Waiting for chain running error!\n");
                return_status = -1;
                goto cleanup;
            }

            is_restart = true;
        }
    }
    db = crust::DataBase::get_instance();

    // Do restart related
    if (is_restart || g_upgrade_flag)
    {
        // Get srd remaining task
        if (CRUST_SUCCESS == db->get(WL_SRD_REMAINING_TASK, srd_task_str))
        {
            std::stringstream sstream(srd_task_str);
            size_t srd_task_remain = 0;
            sstream >> srd_task_remain;
            srd_task = std::max(srd_task, srd_task_remain);
        }
        // Print recovered workload
        std::string wl_info = ed->gen_workload_str(srd_task);
        p_log->info("Workload information:\n%s\n", wl_info.c_str());
        p_log->info("Restore enclave data successfully, sworker is running now.\n");
    }

    // Restore or add srd task
    if (srd_task > 0)
    {
        p_log->info("Detect %ldGB srd task, will execute later.\n", srd_task);
        if (SGX_SUCCESS != (sgx_status = Ecall_change_srd_task(global_eid, &crust_status, srd_task, &srd_real_change)))
        {
            p_log->err("Set srd change failed!Invoke SGX api failed! Error code:%lx\n", sgx_status);
        }
        else
        {
            switch (crust_status)
            {
            case CRUST_SUCCESS:
                p_log->info("Add srd task successfully! %ldG has been added, will be executed later.\n", srd_real_change);
                break;
            case CRUST_SRD_NUMBER_EXCEED:
                p_log->warn("Add srd task failed! Srd number has reached the upper limit! Real srd task is %ldG.\n", srd_real_change);
                break;
            default:
                p_log->info("Unexpected error has occurred!\n");
            }
        }
    }

    // Start http service
    if (!start_task(start_webservice))
    {
        p_log->err("Start web service failed!\n");
        goto cleanup;
    }

    // Check block height and post report to chain
    start_task(work_report_loop);

    // Start thread to check srd reserved
    start_task(srd_check_reserved);

    // Main validate loop
    start_task(main_loop);

    // Check loop
    while (true)
    {
        // Deal with upgrade
        if (UPGRADE_STATUS_PROCESS == ed->get_upgrade_status())
        {
            if (EnclaveQueue::get_instance()->get_upgrade_ecalls_num() == 0)
            {
                ed->set_upgrade_status(UPGRADE_STATUS_END);
            }
        }
        if (UPGRADE_STATUS_END == ed->get_upgrade_status())
        {
            p_log->info("Start generating upgrade data...\n");
            crust::BlockHeader block_header;
            if (!crust::Chain::get_instance()->get_block_header(block_header))
            {
                p_log->err("Get block header failed! Please check your crust-api and crust chain!\n");
            }
            else if (SGX_SUCCESS != (sgx_status = Ecall_gen_upgrade_data(global_eid, &crust_status, block_header.number)))
            {
                p_log->err("Generate upgrade metadata failed! Invoke SGX API failed! Error code:%lx. Try next turn!\n", sgx_status);
            }
            else if (CRUST_SUCCESS != crust_status)
            {
                p_log->warn("Generate upgrade metadata failed! Code:%lx. Try next turn!\n", crust_status);
            }
            else
            {
                p_log->info("Generate upgrade metadata successfully!\n");
                ed->set_upgrade_status(UPGRADE_STATUS_COMPLETE);
            }
        }

        // Upgrade tryout
        if (UPGRADE_STATUS_NONE != ed->get_upgrade_status())
        {
            if (--upgrade_tryout < 0)
            {
                p_log->err("Upgrade timeout!Current version will restore work!\n");
                ed->set_upgrade_status(UPGRADE_STATUS_NONE);
                upgrade_tryout = upgrade_timeout / check_interval;
            }
        }
        else
        {
            // Restore related work
            if (!restore_tasks())
            {
                p_log->err("Restore tasks failed! Will exist...\n");
                goto cleanup;
            }
        }

        // Sleep and check exit flag
        if (!sleep_interval(check_interval, [&ed](void) {
            if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status())
            {
                // Wait tasks end
                bool has_task_running = false;
                for (auto task : g_tasks_m)
                {
                    if(task.first == start_webservice)
                    {
                        continue;
                    }
                    if (task.second->wait_for(std::chrono::seconds(0)) != std::future_status::ready)
                    {
                        has_task_running = true;
                    }
                }
                return has_task_running;
            }
            return true;
        })) { goto cleanup; }
    }

cleanup:
    // Release database
    p_log->info("Release database for exit...\n");
    if (db != NULL)
    {
        delete db;
    }

    // Stop web service
    p_log->info("Kill web service for exit...\n");
    stop_webservice();

    // Destroy enclave
    // TODO: Fix me, why destory enclave leads to coredump
    p_log->info("Destroy enclave for exit...\n");
    if (global_eid != 0)
    {
        sgx_destroy_enclave(global_eid);
    }

    return return_status;
}
