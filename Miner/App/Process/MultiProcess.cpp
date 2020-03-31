#include "MultiProcess.h"
#include "OCalls.h"
#include <map>
#include <fstream>

#define RECEIVE_PID_RETRY 30
#define IPC_RETRY 10

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid;
// Indicate if run current process as server
// Record monitor and worker process id
pid_t workerPID = -1, monitorPID = -1, monitor2PID = -1;
// Local attestation session type
int g_session_type;
// Heart beat timeout between monitor and worker process
const int heart_beat_timeout = 15;
// Indicate if exit whole process
bool g_exit_process = false;
// Indicate current process in show info
const char *g_show_tag = "";
// Pointor to configure instance
Config *p_config = NULL;
// Pointer to http handler instance
ApiHandler *p_api_handler = NULL;

/* monitor and worker ipc related */
Ipc *g_wl_ipc = NULL; // workload ipc
Ipc *g_kp_ipc = NULL; // key pair ipc
Ipc *g_mw_ipc = NULL; // monitor worker ipc

/* Should be shared between monitor and worker */
// Indicate if entry network has been done
bool g_entried_network = false;
// Indicate if entry network has been done
bool g_entried_chain = false;
// indicates whether received workload or not
bool g_monitor_recv_workload = false; 
// Store tee identity
std::string g_entry_net_res = "";

extern FILE *felog;
extern bool run_as_server;
extern bool offline_chain_mode;

void start_monitor(void);
void start_monitor2(void);
void start_worker(void);
bool wait_chain_run(void);
ipc_status_t attest_session(attest_data_type_t data_type, bool starter);
bool do_plot_disk(void);
void *do_workload_receive(void*);
bool send_msg(monitor_worker_msg_t msg_type);
bool recv_msg();
void empty_ipc();

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
        recv_msg();
        break;
    case SIGUSR2:
        g_exit_process = true;
        break;
    case SIGCHLD:
        /* Deal with child process */
        // Check if there is any child process existed before existing
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        {
            if (WIFEXITED(status))
            {
                cprintf_info(felog, "child %d terminated!Error code:%lx\n", 
                         pid, WEXITSTATUS(status));
            }
            else
            {
                cprintf_info(felog, "child %d terminated!Error code:%lx\n", 
                         pid, status);
            }
        }
        break;
    }
}

/**
 * @description: Erase all messages in three message queue
 * */
void empty_ipc()
{
    msg_form_t msg;
    while (msgrcv(g_mw_ipc->msqid, &msg, sizeof(msg.text), 0, IPC_NOWAIT) != -1);
    while (msgrcv(g_kp_ipc->msqid, &msg, sizeof(msg.text), 0, IPC_NOWAIT) != -1);
    while (msgrcv(g_wl_ipc->msqid, &msg, sizeof(msg.text), 0, IPC_NOWAIT) != -1);
}

/**
 * @description: Send data to another thread
 * @param msg_type -> indicate to be sent data type
 * @param pid -> the receiver process id
 * @return: Send message and receive reply successfully or not
 * */
bool send_msg(monitor_worker_msg_t msg_type, pid_t pid)
{
    msg_form_t msg;
    msg.type = msg_type;

    // Put data to shared memory
    if (msg.type == MW_MSG_ENTRYNETWORK)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(g_mw_ipc->shm, &g_entried_network, sizeof(g_entried_network));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Send entried network:%d(type:%d)!\n",
                 g_entried_network, msg.type);
    }
    else if (msg.type == MW_MSG_ENTRYCHAIN)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(g_mw_ipc->shm, &g_entried_chain, sizeof(g_entried_chain));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Send entried chain:%d(type:%d)!\n",
                 g_entried_chain, msg.type);
    }
    else if (msg.type == MW_MSG_WORKER_PID)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(g_mw_ipc->shm, &workerPID, sizeof(workerPID));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Send workerPID:%d(type:%d)!\n",
                 workerPID, msg.type);
    }
    else if (msg.type == MW_MSG_MONITOR_PID)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(g_mw_ipc->shm, &monitorPID, sizeof(monitorPID));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Send monitorPID:%d(type:%d)!\n",
                 monitorPID, msg.type);
    }
    else if (msg.type == MW_MSG_ENTRYNETWORK_DATA)
    {
        msg.text = g_entry_net_res.size();
        cprintf_info(felog, "entry result size:%d, gsize:%d\n", msg.text, g_entry_net_res.size());
        sem_p(g_mw_ipc->semid);
        memcpy(g_mw_ipc->shm, g_entry_net_res.c_str(), g_entry_net_res.size());
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Send monitorPID:%d(type:%d)!\n",
                 monitorPID, msg.type);
    }
    else
    {
        cprintf_info(felog, "Can't send unknown message type:%d!\n", msg.type);
        return false;
    }

    // Send data
    if (msgsnd(g_mw_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        cprintf_err(felog, "Send message type:%d failed!Error:%s\n",
                 msg_type, strerror(errno));
        return false;
    }
    // Notify receiver to receive
    if (kill(pid, SIGUSR1) == -1)
    {
        cprintf_err(felog, "Send notification failed!\n");
        return false;
    }

    msg.type++;
    if (Msgrcv_to(g_mw_ipc->msqid, &msg, sizeof(msg.text), msg.type) == -1)
    {
        cprintf_err(felog, "Receive message type:%d failed!\n", msg.type);
        return false;
    }
    cprintf_info(felog, "Receive reply(type:%d) successfully!\n", msg.type);

    return true;
}

/**
 * @description: Receive message from message queue
 * @return: Receive message successfully or not
 * */
bool recv_msg()
{
    int ipc_retry = IPC_RETRY;
    msg_form_t msg;
    // Wait message
    while (ipc_retry > 0)
    {
        if (Msgrcv_to(g_mw_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
        {
            cprintf_err(felog, "Receive message failed!\n");
            return false;
        }
        ipc_retry--;
        if (msg.type < 400 || msg.type > 500)
            continue;
        break;
    }

    // Get data
    if (msg.type == MW_MSG_ENTRYNETWORK)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(&g_entried_network, g_mw_ipc->shm, sizeof(g_entried_network));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Get entried network:%d(type:%d)!\n",
                 g_entried_network, msg.type);
    }
    else if (msg.type == MW_MSG_ENTRYCHAIN)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(&g_entried_chain, g_mw_ipc->shm, sizeof(g_entried_chain));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Get entried chain:%d(type:%d)!\n",
                 g_entried_chain, msg.type);
    }
    else if (msg.type == MW_MSG_WORKER_PID)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(&workerPID, g_mw_ipc->shm, sizeof(workerPID));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Get workerPID:%d(type:%d)!\n",
                 workerPID, msg.type);
    }
    else if (msg.type == MW_MSG_MONITOR_PID)
    {
        sem_p(g_mw_ipc->semid);
        memcpy(&monitorPID, g_mw_ipc->shm, sizeof(monitorPID));
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Get monitorPID:%d(type:%d)!\n",
                 monitorPID, msg.type);
    }
    else if (msg.type == MW_MSG_ENTRYNETWORK_DATA)
    {
        sem_p(g_mw_ipc->semid);
        cprintf_info(felog, "Get entry network size:%d\n",
                 msg.text);
        g_entry_net_res = std::string(g_mw_ipc->shm, msg.text);
        sem_v(g_mw_ipc->semid);
        cprintf_info(felog, "Get entry network result(type:%d):%s!\n",
                 msg.type, g_entry_net_res.c_str());
    }
    else
    {
        cprintf_info(felog, "Receive unknown message type:%d!\n", msg.type);
        return false;
    }

    // Send response
    msg.type++;
    if (msgsnd(g_mw_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        cprintf_err(felog, "Send message type:%d failed!\n",
                 msg.type);
        return false;
    }
    cprintf_info(felog, "send back type:%d successfully!\n", msg.type);

    return true;

}

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
 * @description: New three ipc objects
 * @return: Create three ipc objects successfully or not
 * */
bool initialize_ipc(void)
{
    std::ofstream(WL_FILE_PATH);
    std::ofstream(KP_FILE_PATH);
    std::ofstream(MW_FILE_PATH);
    // Create workload ipc
    g_wl_ipc = new Ipc();
    if (!g_wl_ipc->init(WL_FILE_PATH, WL_IPC_NUM))
    {
        cprintf_err(felog, "Init workload ipc failed!\n");
        return false;
    }

    // Create key pair ipc
    g_kp_ipc = new Ipc();
    if (!g_kp_ipc->init(KP_FILE_PATH, KP_IPC_NUM))
    {
        cprintf_err(felog, "Init key pair ipc failed!\n");
        return false;
    }

    // Create monitor worker ipc
    g_mw_ipc = new Ipc();
    if (!g_mw_ipc->init(MW_FILE_PATH, MW_IPC_NUM))
    {
        cprintf_err(felog, "Init monitor worker ipc failed!\n");
        return false;
    }

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

    /* Generate ecc key pair */
    if (g_session_type == SESSION_STARTER)
    {
        if (SGX_SUCCESS != ecall_gen_key_pair(global_eid, &ret))
        {
            cprintf_err(felog, "Generate key pair failed!\n");
            return false;
        }
        cprintf_info(felog, "Generate key pair successfully!\n");
    }
    cprintf_info(felog, "Initial enclave successfully!\n");

    return true;
}

/**
 * @description: Start http service
 * */
void *start_http(void *)
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
bool initialize_components(void)
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
    if (pthread_create(&wthread, NULL, start_http, NULL) != 0)
    {
        cprintf_err(felog, "Create rest service thread failed!\n");
        return false;
    }
    cprintf_info(felog, "Start rest service successfully!\n");

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
    req_data.append("{ \"isvEnclaveQuote\": \"");
    req_data.append(b64quote).append("\", \"crust_address\": \"");
    req_data.append(p_config->crust_address).append("\", \"crust_account_id\": \"");
    req_data.append(p_config->crust_account_id.c_str()).append("\" }");
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
bool wait_chain_run(void)
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
 * @description: Execute different session based on parameter
 * @return: session result
 * */
ipc_status_t attest_session(attest_data_type_t data_type)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    ipc_status_t ipc_status = IPC_SUCCESS;
    const char *p_data_type;
    if (data_type == ATTEST_DATATYPE_KEYPAIR)
    {
        p_data_type = "key pair";
    }
    else if (data_type == ATTEST_DATATYPE_WORKLOAD)
    {
        p_data_type = "workload";
    }

    if (g_session_type == SESSION_STARTER)
    {
        cprintf_info(felog, "Do %s attestation(starter)...\n", p_data_type);
        sgx_status = ecall_attest_session_starter(global_eid, &ipc_status, data_type);
    }
    else if (g_session_type == SESSION_RECEIVER)
    {
        cprintf_info(felog, "Do %s attestation(receiver)...\n", p_data_type);
        sgx_status = ecall_attest_session_receiver(global_eid, &ipc_status, data_type);
    }
    else
    {
        return IPC_BADSESSIONTYPE;
    }
    // Judge by result
    if (SGX_SUCCESS != sgx_status)
    {
        ipc_status =  IPC_SGX_ERROR;
    }

    if (IPC_SUCCESS != ipc_status)
    {
        cprintf_err(felog, "Do %s attestation failed!Error code:%lx\n", 
                p_data_type, ipc_status);
    }
    else
    {
        cprintf_info(felog, "Do %s attestation successfully!\n", p_data_type);
    }


    return ipc_status;
}

/**
 * @description: Check if there is enough height, send signed validation report to chain
 * */
void *do_upload_work_report(void *)
{
    while (true)
    {
        BlockHeader *block_header = get_crust()->get_block_header();
        if (block_header->number % BLOCK_HEIGHT == 0)
        {
            sleep(20);
            size_t report_len = 0;
            sgx_ec256_signature_t ecc_signature;
            common_status_t common_status = CRUST_SUCCESS;
            // Generate validation report and get report size
            if (ecall_generate_validation_report(global_eid, &report_len) != SGX_SUCCESS)
            {
                cprintf_err(felog, "Generate validation report failed!\n");
                continue;
            }

            // Get signed validation report
            char *report = (char *)malloc(report_len);
            memset(report, 0, report_len);
            if (ecall_get_signed_validation_report(global_eid, &common_status,
                                                   block_header->hash.c_str(), block_header->number, &ecc_signature, report, report_len) != SGX_SUCCESS)
            {
                cprintf_err(felog, "Get signed validation report failed!\n");
            }
            else
            {
                if (common_status == CRUST_SUCCESS)
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
                else if (common_status == CRUST_BLOCK_HEIGHT_EXPIRED)
                {
                    cprintf_info(felog, "Block height expired.\n");
                }
                else
                {
                    cprintf_err(felog, "Get signed validation report failed! Error code:%x\n", common_status);
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
 * @description: Thread work function to receive workload from worker
 * */
void *do_workload_receive(void*)
{
    ipc_status_t ipc_status = IPC_SUCCESS;
    while(true)
    {
        if(IPC_SUCCESS == (ipc_status = attest_session(ATTEST_DATATYPE_WORKLOAD)))
        {
            // If the newest workload not recevied? 
            g_monitor_recv_workload = true;
        }
        pthread_testcancel();
        sleep(5);
    }

}

/**
 * @description: Do disk related
 */
void *do_disk_related(void *args)
{
    bool need_plot_disk = *((bool *)args);
    pthread_t wthread;

    /* Plot empty disk */
    if (need_plot_disk)
    {
        if (!do_plot_disk())
        {
            cprintf_err(felog, "Plot empty disk failed!\n");
            return NULL; 
        }
        cprintf_info(felog, "Plot empty disk successfully!\n");
    }
    else
    {
        cprintf_info(felog, "Have received workload from monitor successfully!\n");
    }

    if (!offline_chain_mode)
    {
        if (new_crust(p_config->crust_api_base_url, p_config->crust_password, p_config->crust_backup) == NULL)
        {
            cprintf_err(felog, "Init crust chain failed.\n");
            return NULL;
        }
    
        /* Send identity to crust chain */
        if (!wait_chain_run())
        {
            return NULL;
        }
        
        if (!g_entried_chain)
        {
            if (!get_crust()->post_tee_identity(g_entry_net_res))
            {
                cprintf_err(felog, "Send identity to crust chain failed!\n");
                return NULL;
            }
            cprintf_info(felog, "Send identity to crust chain successfully!\n");
            g_entried_chain = true;
            send_msg(MW_MSG_ENTRYCHAIN, monitorPID);
        }
    
        // Check block height and post report to chain
        if (pthread_create(&wthread, NULL, do_upload_work_report, NULL) != 0)
        {
            cprintf_err(felog, "Create checking block info thread failed!\n");
        }
    }

    /* Main validate loop */
    ecall_main_loop(global_eid, p_config->empty_path.c_str(), p_config->recover_file_path.c_str());

    return NULL;
}

/**
 * @description: plot disk
 * @return: successed or failed
 */
bool do_plot_disk(void)
{
    size_t free_space = get_free_space_under_directory(p_config->empty_path) / 1024;
    cprintf_info(felog, "Free space is %luG disk\n", free_space);
    size_t true_plot= free_space <= 10 ? 0 : std::min(free_space - 10, p_config->empty_capacity);
    cprintf_info(felog, "Start ploting disk %luG (plot thread number: %d) ...\n", true_plot, p_config->plot_thread_num);
    // Use omp parallel to plot empty disk, the number of threads is equal to the number of CPU cores
    #pragma omp parallel for num_threads(p_config->plot_thread_num)
    for (size_t i = 0; i < true_plot; i++)
    {
        ecall_plot_disk(global_eid, p_config->empty_path.c_str());
    }

    cprintf_info(felog, "Plot disk %luG successed.\n", true_plot);

    return true;
}

/**
 * @description: This function used to monitor worker process status,
 *  if worker process is terminated, restart it again
 */
void start_monitor(void)
{
    g_show_tag = "<monitor>";
    monitorPID = getpid();
    cprintf_info(felog, "MonitorPID=%d\n", monitorPID);
    ipc_status_t ipc_status = IPC_SUCCESS;
    pid_t pid = -1;
    std::map<std::string, pid_t> pids_m;
    pids_m["worker"] = workerPID;
    pids_m["monitor2"] = monitor2PID;
    bool is_break_check = false;
    bool doAttest = true; // Used to indicate if worker terminated
    std::pair<std::string, pid_t> exit_entry;
    g_monitor_recv_workload = false;
    pthread_t wthread;
    void *wthread_ret = NULL;

    /* Signal function */
    // SIGUSR1 used to notify that entry network has been done,
    // no need to do it again
    signal(SIGUSR1, sig_handler);
    // SIGUSR2 used to notify monitor process to exit
    signal(SIGUSR2, sig_handler);
    signal(SIGCHLD, sig_handler);

    /* Init IPC */
    if (!initialize_ipc())
    {
        cprintf_err(felog, "Init IPC failed!\n");
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
        cprintf_err(felog, "Monitor process init enclave failed!\n");
        ipc_status = INIT_ENCLAVE_ERROR;
        goto cleanup;
    }
    cprintf_info(felog, "Monitor process init enclave successfully!id:%d\n", 
             global_eid);

again:
    /* Do local attestation and exchange pid with worker */
    if (doAttest)
    {
        // Do key pair attestation
        if (IPC_SUCCESS != (ipc_status = attest_session(ATTEST_DATATYPE_KEYPAIR)))
        {
            goto cleanup;
        }

        /* Send workload to worker or not */
        if (g_session_type == SESSION_STARTER && g_monitor_recv_workload)
        {
            attest_session(ATTEST_DATATYPE_WORKLOAD);
        }
        // Set session type to receiver to receive workload
        g_session_type = SESSION_RECEIVER;
        // Create a thread to receive workload from worker
        if (pthread_create(&wthread, NULL, do_workload_receive, NULL) != 0)
        {
            cprintf_warn(felog, "Create receiver thread failed!\n");
        }
        doAttest = false;
    }

    /* Monitor worker and monitor2 process */
    while (true)
    {
        sleep(heart_beat_timeout);
        for (auto it : pids_m)
        {
            if (kill(it.second, 0) == -1)
            {
                if (errno == ESRCH)
                {
                    cprintf_err(felog, "%s process is not existed!pid:%d\n", 
                             it.first.c_str(), it.second);
                }
                else if (errno == EPERM)
                {
                    cprintf_err(felog, "%s has no right to send signal to worker!\n", 
                             it.first.c_str());
                }
                else if (errno == EINVAL)
                {
                    cprintf_err(felog, "Invalid signal!\n");
                }
                else
                {
                    cprintf_err(felog, "Unknown error!\n");
                }
                cprintf_err(felog, "%s sends signal to worker failed!Error code:%d\n", 
                         it.first.c_str(), errno);
                is_break_check = true;
                exit_entry = it;
                break;
            }
        }
        if (is_break_check)
        {
            break;
        }
    }
    is_break_check = false;
    cprintf_info(felog, "%s process exit unexpectly!Restart it again\n", 
             exit_entry.first.c_str());

    //++++++++++ This session deals with monitor or worker exit unexpectly ++++++++++//

    // Check if worker process exit because of entry network or creating work thread failed,
    // then monitor process should end.
    if (g_exit_process)
    {
        cprintf_err(felog, "Worker process entries network or creates work thread failed! \
                Exit monitor process!\n");
        goto cleanup;
    }

    if (exit_entry.first.compare("worker") == 0)
    {
        // Empty message queue
        empty_ipc();

        // Stop workload receive thread
        cprintf_info(felog, "Stopping workload receive thread...\n");
        pthread_cancel(wthread);
        pthread_join(wthread, &wthread_ret);
        if (wthread_ret != PTHREAD_CANCELED)
        {
            cprintf_err(felog, "Stop workload receiver failed!\n");
        }
    }

    /* Fork new child process */
    cprintf_info(felog, "Do fork\n");
    if ((pid = fork()) == -1)
    {
        cprintf_err(felog, "Create worker process failed!\n");
        ipc_status = FORK_NEW_PROCESS_ERROR;
        goto cleanup;
    }

    if (pid == 0)
    {
        // New child process
        cprintf_info(felog, "Start new %s...\n", exit_entry.first.c_str());
        if (exit_entry.first.compare("worker") == 0)
        {
            // Change session type to receiver, prepare to receive data from monitor
            g_session_type = SESSION_RECEIVER;
            start_worker();
        }
        else if (exit_entry.first.compare("monitor2") == 0)
        {
            start_monitor2();
        }
        else
        {
            cprintf_err(felog, "Unknown process!\n");
            goto cleanup;
        }
    }
    else
    {
        // Monitor process
        if (exit_entry.first.compare("worker") == 0)
        {
            workerPID = pid;
            // Change session type to start, prepare to send data to worker
            g_session_type = SESSION_STARTER;
            // Send workerPID to monitor2
            send_msg(MW_MSG_WORKER_PID, monitor2PID);
            doAttest = true;
        }
        else if (exit_entry.first.compare("monitor2") == 0)
        {
            monitor2PID = pid;
        }
        else
        {
            cprintf_err(felog, "Unknown process!\n");
            goto cleanup;
        }
        // Update related pid
        pids_m[exit_entry.first] = pid;
        goto again;
    }

cleanup:
    /* End and release*/
    if (global_eid != 0)
        sgx_destroy_enclave(global_eid);

    if (g_mw_ipc != NULL)
        delete g_mw_ipc;

    if (g_kp_ipc != NULL)
        delete g_kp_ipc;

    if (g_wl_ipc != NULL)
        delete g_wl_ipc;

    cprintf_err(felog, "Monitor process exits with error code:%lx\n", ipc_status);

    // Send SIGKILL to monitor2 to prevent it starts up monitor again
    cprintf_err(felog, "Kill monitor2 process\n");
    if (kill(pids_m["monitor2"], SIGKILL) == -1)
    {
        cprintf_err(felog, "Send SIGKILL to monitor2 failed!\n");
    }

    if (felog != NULL)
        close_logfile(felog);

    exit(ipc_status);
}

/**
 * @description: Start monitor2 process used to monitor monitor process
 * */
void start_monitor2(void)
{
    g_show_tag = "<monitor2>";
    monitor2PID = getpid();
    cprintf_info(felog, "Monitor2PID=%d\n", monitor2PID);
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
    if (!initialize_ipc())
    {
        cprintf_err(felog, "Init IPC failed!\n");
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }

again:
    /* Monitor worker process */
    while (true)
    {
        sleep(heart_beat_timeout);
        if (kill(monitorPID, 0) == -1)
        {
            if (errno == ESRCH)
            {
                cprintf_err(felog, "Monitor process is not existed!\n");
            }
            else if (errno == EPERM)
            {
                cprintf_err(felog, "Monitor2 has no right to send signal to monitor!\n");
            }
            else if (errno == EINVAL)
            {
                cprintf_err(felog, "Invalid signal!\n");
            }
            else
            {
                cprintf_err(felog, "Unknown error!\n");
            }
            cprintf_err(felog, "Monitor2 sends signal to monitor failed!Error code:%d\n", 
                     errno);
            break;
        }
    }
    cprintf_info(felog, "Monitor process exit unexpectly!Restart it again\n");

    //++++++++++ This session deals with monitor exit unexpectly ++++++++++//

    /* Fork new child process */
    cprintf_info(felog, "Do fork\n");
    // Should get current pid before fork
    if ((pid = fork()) == -1)
    {
        cprintf_err(felog, "Create monitor process failed!\n");
        ipc_status = FORK_NEW_PROCESS_ERROR;
        goto cleanup;
    }
    if (pid == 0)
    {
        // Child process used for monitor
        cprintf_info(felog, "Start new monitor:monitor2:%d...\n", 
                 monitor2PID);
        g_session_type = SESSION_RECEIVER;
        start_monitor();
    }
    else
    {
        monitorPID = pid;
        // Send monitorPID to worker
        send_msg(MW_MSG_MONITOR_PID, workerPID);
        goto again;
    }

cleanup:
    /* End and release*/
    cprintf_err(felog, "Monitor process exits with error code:%lx\n", 
             ipc_status);

    if (g_mw_ipc != NULL)
        delete g_mw_ipc;

    if (g_kp_ipc != NULL)
        delete g_kp_ipc;

    if (g_wl_ipc != NULL)
        delete g_wl_ipc;

    if (felog != NULL)
        close_logfile(felog);

    exit(ipc_status);
}

/**
 * @description: start parent worker
 */
void start_worker(void)
{
    g_show_tag = "<worker>";
    workerPID = getpid();
    cprintf_info(felog, "WorkerPID=%d\n", workerPID);
    pthread_t wthread;
    ipc_status_t ipc_status = IPC_SUCCESS;
    bool need_plot_disk = true;
    pid_t monitorPID_old = monitorPID;
    int receive_pid_retry = 0;
    cprintf_info(felog, "Worker global eid:%d\n", global_eid);

    /* Signal function */
    // SIGUSR1 used to notify that entry network has been done,
    // no need to do it again
    signal(SIGUSR1, sig_handler);
    // If monitor exit unexpectly, monitor will notify worker to do attestation again
    signal(SIGUSR2, sig_handler);
    signal(SIGCHLD, sig_handler);

    /* Init conifigure */
    if (!initialize_config())
    {
        cprintf_err(felog, "Init configuration failed!\n");
        exit(INIT_CONFIG_ERROR);
    }

    /* Init related components */
    if (!initialize_components())
    {
        cprintf_err(felog, "Init component failed!\n");
        ipc_status = INIT_COMPONENT_ERROR;
        goto cleanup;
    }
    cprintf_info(felog, "Init components successfully!\n");

    /* Init IPC */
    if (!initialize_ipc())
    {
        cprintf_err(felog, "Init IPC failed!\n");
        ipc_status = INIT_IPC_ERROR;
        goto cleanup;
    }
    cprintf_info(felog, "Init IPC successfully!\n");

    /* Init enclave */
    if (global_eid != 0)
    {
        // If worker process is copied from fork function,
        // delete copied sgx enclave memory space
        sgx_destroy_enclave(global_eid);
    }
    if (!initialize_enclave())
    {
        cprintf_err(felog, "Init enclave failed!\n");
        ipc_status = INIT_ENCLAVE_ERROR;
        goto cleanup;
    }
    cprintf_info(felog, "Worker process int enclave successfully!id:%d\n", 
             global_eid);
    if (SGX_SUCCESS != ecall_set_run_mode(global_eid, APP_RUN_MODE_MULTIPLE, strlen(APP_RUN_MODE_MULTIPLE)))
    {
        cprintf_err(felog, "Set TEE run mode failed!\n");
    }

    /* Do TEE key pair transformation */
    if (IPC_SUCCESS != (ipc_status = attest_session(ATTEST_DATATYPE_KEYPAIR)))
    {
        goto cleanup;
    }
    else
    {
        // Do workload transformation or not
        if (g_session_type == SESSION_RECEIVER && g_monitor_recv_workload)
        {
            if (IPC_SUCCESS == (ipc_status = attest_session(ATTEST_DATATYPE_WORKLOAD)))
            {
                need_plot_disk = false;
            }
        }
        g_session_type = SESSION_STARTER;
    }

    /* Entry network */
    if (!g_entried_network && !run_as_server)
    {
        cprintf_info(felog, "Entrying network...\n");
        if (!entry_network())
        {
            ipc_status = ENTRY_NETWORK_ERROR;
            goto cleanup;
        }
        cprintf_info(felog, "Entry network application successfully!Info:%s\n", 
                 g_entry_net_res.c_str());
        // Notify monitor that worker has entried network successfully
        g_entried_network = true;
        send_msg(MW_MSG_ENTRYNETWORK, monitorPID);
        send_msg(MW_MSG_ENTRYNETWORK_DATA, monitorPID);
    }
    
    /* Do Validate disk */
    if (pthread_create(&wthread, NULL, do_disk_related, (void*)&need_plot_disk) != 0)
    {
        cprintf_err(felog, "Create worker thread failed!\n");
        ipc_status = IPC_CREATE_THREAD_ERR;
        goto cleanup;
    }

again:
    /* Monitor monitor process */
    while (true && monitorPID_old == monitorPID)
    {
        sleep(heart_beat_timeout);
        if (kill(monitorPID, 0) == -1)
        {
            if (errno == ESRCH)
            {
                cprintf_err(felog, "Monitor process is not existed!\n");
            }
            else if (errno == EPERM)
            {
                cprintf_err(felog, "Worker has no right to send signal to monitor!\n");
            }
            else if (errno == EINVAL)
            {
                cprintf_err(felog, "Invalid signal!\n");
            }
            else
            {
                cprintf_err(felog, "Unknown error!\n");
            }
            cprintf_err(felog, "Worker sends signal to monitor failed!Error code:%d\n", 
                     errno);
            break;
        }
    }


    //++++++++++ This session deals with data needed transfered to monitor ++++++++++//

    // Empty message queue
    empty_ipc();

    // Wait for receiving monitorPID
    receive_pid_retry = RECEIVE_PID_RETRY;
    while(receive_pid_retry > 0)
    {
        if (monitorPID_old != monitorPID)
            break;
        receive_pid_retry--;
        sleep(1);
    }
    monitorPID_old = monitorPID;
    
    /* Do TEE key pair transformation */
    // Change session type to starter
    g_session_type = SESSION_STARTER;
    if (IPC_SUCCESS != (ipc_status = attest_session(ATTEST_DATATYPE_KEYPAIR)))
    {
        goto cleanup;
    }

    // Send related info to monitor
    send_msg(MW_MSG_ENTRYNETWORK, monitorPID);
    send_msg(MW_MSG_ENTRYCHAIN, monitorPID);
    send_msg(MW_MSG_ENTRYNETWORK_DATA, monitorPID);

    goto again;


cleanup:
    /* End and release */
    delete p_config;
    if (get_ipfs() != NULL)
        delete get_ipfs();

    if (p_api_handler != NULL)
        delete p_api_handler;

    if (global_eid != 0)
        sgx_destroy_enclave(global_eid);

    if (g_mw_ipc != NULL)
        delete g_mw_ipc;

    if (g_kp_ipc != NULL)
        delete g_kp_ipc;

    if (g_wl_ipc != NULL)
        delete g_wl_ipc;

    // If entry network or create work thread failed, notify monitor process to exit
    if (ENTRY_NETWORK_ERROR == ipc_status || IPC_CREATE_THREAD_ERR == ipc_status)
    {
        kill(monitorPID, SIGUSR2);
    }

    cprintf_err(felog, "Worker process exits with error code:%lx\n", ipc_status);

    if (felog != NULL)
        close_logfile(felog);

    exit(ipc_status);
}

/**
 * @desination: Main function to start application
 * @return: Start status
 * */
int multi_process_run()
{
    // Clean last time IPC related variable, actually it indicates message queue
    // generated last time without normal exit
    clean_ipc();

    // Create log file
    if (felog == NULL)
        felog = create_logfile(LOG_FILE_PATH);

    // Create worker process
    monitorPID = getpid();
    pid_t pid;
    if ((pid = fork()) == -1)
    {
        cprintf_err(felog, "Create worker process failed!\n");
        return -1;
    }
    if (pid == 0)
    {
        // Worker process(child process)
        g_session_type = SESSION_STARTER;
        start_worker();
    }
    else
    {
        // Monitor process(parent process)
        workerPID = pid;
        if ((pid = fork()) == -1)
        {
            cprintf_err(felog, "Create worker process failed!\n");
            return -1;
        }
        if (pid == 0)
        {
            start_monitor2();
        }
        else
        {
            monitor2PID = pid;
            g_session_type = SESSION_RECEIVER;
            start_monitor();
        }
    }

    return 1;
}
