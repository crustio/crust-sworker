#include "Process.h"
#include "DataBase.h"
#include "WebServer.h"
#include "EntryNetwork.h"
#include "Chain.h"

#include <future>
#include <chrono>

#define RECEIVE_PID_RETRY 30

bool upgrade_try_start();
bool upgrade_try_restore();
bool upgrade_try_complete(bool restore_res);

// Global EID shared by multiple threads
sgx_enclave_id_t global_eid;
// Pointor to configure instance
Config *p_config = NULL;
// Map to record specific task
std::vector<std::pair<std::shared_ptr<std::future<void>>, task_func_t>> g_tasks_v;

crust::Log *p_log = crust::Log::get_instance();
extern bool offline_chain_mode;
extern int g_start_server_success;
extern bool g_upgrade_flag;

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
            p_log->err("Intel SGX is supported on this sytem but not available for use. \
                    The system may lock BIOS support, or the Platform Software is not available\n");
            return false;
        }
    }

    // ----- Launch the enclave ----- //
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

    // ----- Generate code measurement ----- //
    if (SGX_SUCCESS != Ecall_gen_sgx_measurement(global_eid, &ret))
    {
        p_log->err("Generate code measurement failed!error code:%lx\n", ret);
        return false;
    }

    p_log->info("Initial enclave successfully!Enclave id:%d\n", global_eid);

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
    if (!create_directory(p_config->base_path))
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

    // Start http service
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
            std::async(std::launch::async, &start_webservice)), &start_webservice));
    while (g_start_server_success == -1);
    if (g_start_server_success == 0)
    {
        p_log->err("Start web service failed!\n");
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
    int tryout = UPGRADE_START_TRYOUT / start_wait_time;
    int tryout_idx = 0;
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
            if (res_inform.body().compare(err_msg) != 0 || tryout_idx % 15 == 0)
            {
                p_log->info("Old version not ready for upgrade!Message:%s, status:%d, try again...\n", res_inform.body().c_str(), res_inform.result());
                err_msg = res_inform.body();
            }
            if (++tryout_idx > tryout)
            {
                p_log->warn("Upgrade tryout!Message:%s\n", res_inform.body().c_str());
                return false;
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
    int tryout = UPGRADE_META_TRYOUT / meta_wait_time;
    int tryout_idx = 0;
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
            if (res_meta.body().compare(err_msg) != 0 || tryout_idx % 15 == 0)
            {
                p_log->info("Old version Message:%s\n", res_meta.body().c_str());
                err_msg = res_meta.body();
            }
            if (++tryout_idx > tryout)
            {
                p_log->err("Upgrade: restore tryout!\n");
                return false;
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
    size_t meta_offset = 0;
    size_t meta_size = res_meta.body().size();
    const char *p_meta = res_meta.body().c_str();
    while (meta_size > meta_offset)
    {
        size_t partial_size = std::min(meta_size - meta_offset, (size_t)OCALL_STORE_THRESHOLD);
        bool transfer_end = (meta_offset + partial_size >= meta_size);
        sgx_status = Ecall_restore_from_upgrade(global_eid, &crust_status, p_meta + meta_offset, partial_size, meta_size, transfer_end);
        if (SGX_SUCCESS != sgx_status)
        {
            p_log->err("Invoke SGX API failed!Error code:%lx.\n", sgx_status);
            return false;
        }
        else if (CRUST_SUCCESS == crust_status)
        {
            break;
        }
        else if (CRUST_INIT_QUOTE_FAILED == crust_status)
        {
            if (--restore_tryout > 0)
            {
                sgx_destroy_enclave(global_eid);
                sleep(60);
                goto restore_try_again;
            }
            else
            {
                return false;
            }
        }
        else if (CRUST_UPGRADE_NEED_LEFT_DATA == crust_status)
        {
            meta_offset += partial_size;
        }
        else
        {
            p_log->err("Restore workload from upgrade data failed!Error code:%lx.\n", crust_status);
            return false;
        }
    }
    p_log->info("Restore workload from upgrade data successfully!\n");

    return true;
}

/**
 * @description: Inform old version upgrade result
 * @param restore_res -> Upgrade try restore result
 * @return: Inform result
 */
bool upgrade_try_complete(bool restore_res)
{
    std::shared_ptr<HttpClient> client(new HttpClient());
    ApiHeaders headers = {{"backup",p_config->chain_backup}};
    p_log->info("Informing old version upgrade result...\n");
    json::JSON upgrade_ret;
    upgrade_ret["success"] = restore_res;
    int complete_wait_time = 1;
    int tryout = UPGRADE_COMPLETE_TRYOUT / complete_wait_time;
    while (true)
    {
        // Inform old version to close
        http::response<http::string_body> res_complete = client->Get(p_config->base_url + "/upgrade/complete", upgrade_ret.dump(), headers);
        if ((int)res_complete.result() != 200 && (int)res_complete.result() != 404 && --tryout > 0)
        {
            p_log->warn("Inform old version failed!Message:%s, try again...\n", res_complete.body().c_str());
            sleep(complete_wait_time);
            continue;
        }
        break;
    }
    p_log->info("Inform old version that upgrade result: %s!\n", upgrade_ret["success"].ToBool() ? "successfully" : "failed");
    bool res = upgrade_ret["success"].ToBool();

    // Init related components
    if (res)
    {
        p_log->info("Waiting for old version's webservice stop...\n");
        // Waiting old version stop
        int check_old_api_tryout = 200;
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
            if (--check_old_api_tryout < 0)
            {
                p_log->err("Wait old version stop failed!\n");
                break;
            }
            sleep(3);
        }
        sleep(10);
        if (!initialize_components())
        {
            p_log->err("Init component failed!\n");
            res = false;
        }
    }

    return res;
}

/**
 * @description: Check if upgrade
 * @return: Check status
 */
bool do_upgrade()
{
    bool res = true;
    if (!upgrade_try_start())
    {
        return false;
    }

    res = upgrade_try_restore();

    res = upgrade_try_complete(res);

    return res;
}

/**
 * @description: Wrapper for main loop
 */
void main_loop(void)
{
    Ecall_main_loop(global_eid);
}

/**
 * @desination: Main function to start application
 * @return: Start status
 */
int process_run()
{
    pid_t worker_pid = getpid();
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    int return_status = 1;
    int check_interval = 15;
    int upgrade_timeout = 5 * REPORT_BLOCK_HEIGHT_BASE * BLOCK_INTERVAL;
    int upgrade_tryout = upgrade_timeout / check_interval;
    int entry_tryout = 3;
    size_t srd_task = 0;
    long srd_real_change = 0;
    std::string srd_task_str;
    EnclaveData *ed = EnclaveData::get_instance();
    p_log->info("WorkerPID = %d\n", worker_pid);

    // Init conifigure
    if (!initialize_config())
    {
        p_log->err("Init configuration failed!\n");
        return_status = -1;
        goto cleanup;
    }

    // There are three startup mode: upgrade, restore and normal
    // Upgrade mode will communicate with old version for data transferring.
    // Resotre mode will restore enclave data from database.
    // Normal mode will start up a new enclave.
    // ----- Upgrade mode ----- //
    if (g_upgrade_flag)
    {
        // Check and do upgrade
        if (!do_upgrade())
        {
            return_status = -1;
            goto cleanup;
        }
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
            p_log->info("Starting a new enclave...(code:%lx)\n", crust_status);

            // Generate ecc key pair
            if (SGX_SUCCESS != Ecall_gen_key_pair(global_eid, &sgx_status, p_config->chain_account_id.c_str(), p_config->chain_account_id.size())
                    || SGX_SUCCESS != sgx_status)
            {
                p_log->err("Generate key pair failed!\n");
                return_status = -1;
                goto cleanup;
            }
            p_log->info("Generate key pair successfully!\n");

            // Get id info
            if (SGX_SUCCESS != Ecall_id_get_info(global_eid))
            {
                p_log->err("Get id info from enclave failed!\n");
                return_status = -1;
                goto cleanup;
            }

            // Send identity to chain and send work report
            if (!offline_chain_mode)
            {
                // Entry network
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

            p_log->info("Workload information:\n%s\n", ed->gen_workload().c_str());
            p_log->info("Restore enclave data successfully, sworker is running now.\n");
        }
    }

    // Get srd remaining task
    if (CRUST_SUCCESS == crust::DataBase::get_instance()->get(WL_SRD_REMAINING_TASK, srd_task_str))
    {
        std::stringstream sstream(srd_task_str);
        size_t srd_task_remain = 0;
        sstream >> srd_task_remain;
        srd_task = std::max(srd_task, srd_task_remain);
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
                p_log->warn("Add srd task failed!Srd number has reached the upper limit! Real srd task is %ldG.\n", srd_real_change);
                break;
            default:
                p_log->info("Unexpected error has occurred!\n");
            }
        }
    }

    // Restore sealed file information
    ed->restore_sealed_file_info();

    // Check block height and post report to chain
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
             std::async(std::launch::async, &work_report_loop)), &work_report_loop));

    // Start thread to check srd reserved
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
            std::async(std::launch::async, &srd_check_reserved)), &srd_check_reserved));

    // Main validate loop
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
            std::async(std::launch::async, &main_loop)), &main_loop));

    // Check loop
    while (true)
    {
        // Check if work threads still running
        if (UPGRADE_STATUS_EXIT != ed->get_upgrade_status())
        {
            std::future_status f_status;
            for (auto task : g_tasks_v)
            {
                f_status = task.first->wait_for(std::chrono::seconds(0));
                if (f_status == std::future_status::ready)
                {
                    task.first = std::make_shared<std::future<void>>(std::async(
                            std::launch::async, task.second));
                }
            }
        }

        // Deal with upgrade
        if (UPGRADE_STATUS_PROCESS == ed->get_upgrade_status())
        {
            if (get_upgrade_ecalls_num() == 0)
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
                p_log->err("Generate upgrade metadata failed! Invoke SGX API failed! Error code:%lx.Try next turn!\n", sgx_status);
            }
            else if (CRUST_SUCCESS != crust_status)
            {
                p_log->err("Generate upgrade metadata failed! Error code:%lx.Try next turn!\n", crust_status);
            }
            else
            {
                p_log->info("Generate upgrade metadata successfully!\n");
                ed->set_upgrade_status(UPGRADE_STATUS_COMPLETE);
            }
        }
        if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status())
        {
            // Release database
            delete crust::DataBase::get_instance();
            goto cleanup;
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

        sleep(check_interval);
    }

cleanup:
    // Stop web service
    p_log->info("Kill web service for exit...\n");
    stop_webservice();

    // Destroy enclave
    // TODO: Fix me, why destory enclave leads to coredump
    p_log->info("Destroy enclave for exit...\n");
    sgx_destroy_enclave(global_eid);

    if (ed->get_upgrade_status() == UPGRADE_STATUS_EXIT)
    {
        exit(return_status);
    }

    return return_status;
}
