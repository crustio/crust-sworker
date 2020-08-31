#include "Process.h"
#include "DataBase.h"
#include "WebServer.h"
#include "EntryNetwork.h"
#include "Chain.h"
#include "tbb/concurrent_unordered_map.h"

#include <future>
#include <chrono>

#define RECEIVE_PID_RETRY 30

// Global EID shared by multiple threads
sgx_enclave_id_t global_eid;
// Pointor to configure instance
Config *p_config = NULL;
// Pointer to http handler instance
ApiHandler *p_api_handler = NULL;
// Map to record specific task
std::vector<std::pair<std::shared_ptr<std::future<void>>, task_func_t>> g_tasks_v;

crust::Log *p_log = crust::Log::get_instance();
extern bool offline_chain_mode;
extern bool g_start_server_success;
extern std::mutex g_start_server_mutex;
extern bool g_init_upgrade;

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
        p_log->err("Init enclave failed.Error code:%08x\n", ret);
        return false;
    }

    // ----- Generate code measurement ----- //
    if (SGX_SUCCESS != Ecall_gen_sgx_measurement(global_eid, &ret))
    {
        p_log->err("Generate code measurement failed!error code:%08x\n", ret);
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
    create_directory(p_config->base_path);

    // Init crust
    if (crust::Chain::get_instance() == NULL)
    {
        p_log->err("Init crust chain failed!\n");
        return false;
    }

    // Start http service
    g_start_server_mutex.lock();
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
            std::async(std::launch::async, &start_webservice)), &start_webservice));
    g_start_server_mutex.lock();
    if (!g_start_server_success)
    {
        p_log->err("Start web service failed!\n");
        g_start_server_mutex.unlock();
        return false;
    }
    g_start_server_mutex.unlock();

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
    std::string tee_identity_result = "";
    int return_status = 1;
    p_log->info("WorkerPID = %d\n", worker_pid);

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
    p_log->info("Worker global eid: %d\n", global_eid);

    // Init upgrade
    if (g_init_upgrade)
    {
        srd_init_upgrade(p_config->srd_capacity);
    }

    // ----- Restore data from file ----- //
    if (SGX_SUCCESS != Ecall_restore_metadata(global_eid, &crust_status) || CRUST_SUCCESS != crust_status)
    {
        // Restore data failed
        p_log->info("Restore enclave data failed!Failed code:%lx.Starting a new enclave...\n", crust_status);
        // Generate ecc key pair
        if (SGX_SUCCESS != Ecall_gen_key_pair(global_eid, &sgx_status) || SGX_SUCCESS != sgx_status)
        {
            p_log->err("Generate key pair failed!\n");
            return_status = -1;
            goto cleanup;
        }
        p_log->info("Generate key pair successfully!\n");

        // Store crust info in enclave
        // TODO: Get srd from other node
        crust_status_t crust_status = CRUST_SUCCESS;
        if (SGX_SUCCESS != Ecall_set_chain_account_id(global_eid, &crust_status,
                p_config->chain_address.c_str(), p_config->chain_address.size())
            || CRUST_SUCCESS != crust_status)
        {
            p_log->err("Store backup information to enclave failed!Error code:%lx\n", crust_status);
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

        // Srd disk
        Ecall_srd_set_change(global_eid, p_config->srd_capacity);
    }
    else
    {
        // Compare crust account it in configure file and recovered file
        if (SGX_SUCCESS != Ecall_cmp_chain_account_id(global_eid, &crust_status,
                p_config->chain_address.c_str(), p_config->chain_address.size())
            || CRUST_SUCCESS != crust_status)
        {
            p_log->err("Configure chain account id doesn't equal to recovered one!\n");
            return_status = -1;
            goto cleanup;
        }

        // Check and do previous srd upgrade
        std::string upgrade_info;
        crust::DataBase *db = crust::DataBase::get_instance();
        if (CRUST_SUCCESS == db->get(SRD_UPGRADE_INFO, upgrade_info) && upgrade_info.size() > 0)
        {
            std::string srd_info;
            long srd_assigned_total = 0;
            if (CRUST_SUCCESS == db->get(DB_SRD_INFO, srd_info) && srd_info.size() > 0)
            {
                json::JSON srd_json = json::JSON::Load(srd_info);
                for (auto it = srd_json.ObjectRange().begin(); it != srd_json.ObjectRange().end(); it++)
                {
                    srd_assigned_total += it->second["assigned"].ToInt();
                }
            }
            json::JSON upgrade_json = json::JSON::Load(upgrade_info);
            if (srd_assigned_total >= upgrade_json[SRD_UPGRADE_INFO_SRD].ToInt())
            {
                db->del(SRD_UPGRADE_INFO);
            }
            else
            {
                upgrade_json[SRD_UPGRADE_INFO_TIMEOUT] = 0;
                db->set(SRD_UPGRADE_INFO, upgrade_json.dump());
                set_reserved_space(DEFAULT_SRD_RESERVED - 10);
                Ecall_srd_set_change(global_eid, upgrade_json[SRD_UPGRADE_INFO_SRD].ToInt() - srd_assigned_total);
            }
        }

        p_log->info("Restore enclave data successfully!\n");

        if (!offline_chain_mode)
        {
            if (!crust::Chain::get_instance()->wait_for_running())
            {
                return_status = -1;
                goto cleanup;
            }
        }
    }

    if (!offline_chain_mode)
    {
        // Check block height and post report to chain
        g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
                std::async(std::launch::async, &work_report_loop)), &work_report_loop));
    }

    // Start thread to check srd reserved
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
            std::async(std::launch::async, &srd_check_reserved)), &srd_check_reserved));

    // Main validate loop
    g_tasks_v.push_back(std::make_pair(std::make_shared<std::future<void>>(
            std::async(std::launch::async, &main_loop)), &main_loop));

    // Check loop
    while (true)
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
        sleep(30);
    }

cleanup:
    // End and release
    delete p_config;

    if (p_api_handler != NULL)
        delete p_api_handler;

    if (global_eid != 0)
        sgx_destroy_enclave(global_eid);

    return return_status;
}
