#include "OCalls.h"

crust::Log *p_log = crust::Log::get_instance();

// Used to store ocall file data
uint8_t *ocall_file_data = NULL;
size_t ocall_file_data_len = 0;
// Used to validation websocket client
WebsocketClient *wssclient = NULL;

extern bool offline_chain_mode;

/**
 * @description: ocall for printing string
 * @param str (in) -> string for printing
 */
void ocall_print_info(const char *str)
{
    printf("%s", str);
}

/**
 * @description: ocall for printing string
 * @param str (in) -> string for printing
 */
void ocall_print_debug(const char *str)
{
    if (p_log->get_debug_flag())
    {
        printf("%s", str);
    }
}

/**
 * @description: ocall for log information
 * @param str (in) -> string for printing
 */
void ocall_log_info(const char *str)
{
    p_log->info("[Enclave] %s", str);
}

/**
 * @description: ocall for log warnings
 * @param str (in) -> string for printing
 */
void ocall_log_warn(const char *str)
{
    p_log->warn("[Enclave] %s", str);
}

/**
 * @description: ocall for log errors
 * @param str (in) -> string for printing
 */
void ocall_log_err(const char *str)
{
    p_log->err("[Enclave] %s", str);
}

/**
 * @description: ocall for log debugs
 * @param str (in) -> string for printing
 */
void ocall_log_debug(const char *str)
{
    p_log->debug("[Enclave] %s", str);
}

/**
 * @description: ocall for wait
 * @param u -> microsecond
 */
void ocall_usleep(int u)
{
    usleep(u);
}

/**
 * @description: Free app buffer
 * @param value (in) -> Pointer points to pointer to value
 * @return: Get status
 */
crust_status_t ocall_free_outer_buffer(uint8_t **value)
{
    if(*value != NULL)
    {
        free(*value);
        *value = NULL;
    }
    
    return CRUST_SUCCESS;
}

/**
 * @description: Get block hash by height
 * @param block_height -> Block height from enclave
 * @param block_hash (in) -> Pointer to got block hash
 * @param hash_size -> Block hash size
 * @return: Get result
 */
crust_status_t ocall_get_block_hash(size_t block_height, char *block_hash, size_t hash_size)
{
    std::string hash = crust::Chain::get_instance()->get_block_hash(block_height);

    if (hash.compare("") == 0)
    {
        return CRUST_UPGRADE_GET_BLOCK_HASH_FAILED;
    }

    memcpy(block_hash, hash.c_str(), hash_size);

    return CRUST_SUCCESS;
}

/**
 * @description: For upgrade, send work report
 * @param work_report (in) -> Work report
 * @return: Send result
 */
crust_status_t ocall_upload_workreport(const char *work_report)
{
    std::string work_str(work_report);
    remove_char(work_str, '\\');
    remove_char(work_str, '\n');
    remove_char(work_str, ' ');
    p_log->info("Sending work report:%s\n", work_str.c_str());
    if (!offline_chain_mode)
    {
        if (!crust::Chain::get_instance()->post_sworker_work_report(work_str))
        {
            return CRUST_UPGRADE_SEND_WORKREPORT_FAILED;
        }
    }

    p_log->info("Send work report to crust chain successfully!\n");

    return CRUST_SUCCESS;
}

/**
 * @description: Entry network
 * @return: Entry result
 */
crust_status_t ocall_entry_network()
{
    return entry_network();
}

/**
 * @description: Do srd in this function
 * @param change -> The change number will be committed this turn
 * @return: Srd change return status
 */
crust_status_t ocall_srd_change(long change)
{
    return srd_change(change);
}

/**
 * @description: Store sworker identity
 * @param id (in) -> Pointer to identity
 * @return: Upload result
 */
crust_status_t ocall_upload_identity(const char *id)
{
    json::JSON entrance_info = json::JSON::Load(std::string(id));
    entrance_info["account_id"] = Config::get_instance()->chain_address;
    std::string sworker_identity = entrance_info.dump();
    p_log->info("Generate identity successfully! Sworker identity: %s\n", sworker_identity.c_str());

    if (!offline_chain_mode)
    {
        // Send identity to crust chain
        if (!crust::Chain::get_instance()->wait_for_running())
        {
            return CRUST_UNEXPECTED_ERROR;
        }

        // ----- Compare mrenclave ----- //
        // Get local mrenclave
        json::JSON id_info;
        for (int i = 0; i < 20; i++)
        {
            std::string id_info_str = EnclaveData::get_instance()->get_enclave_id_info();
            if (id_info_str.compare("") != 0)
            {
                id_info = json::JSON::Load(id_info_str);
                break;
            }
            sleep(3);
            p_log->info("Cannot get id info, try again(%d)...\n", i+1);
        }
        if (!id_info.hasKey("mrenclave"))
        {
            p_log->err("Get sWorker identity information failed!\n");
            return CRUST_UNEXPECTED_ERROR;
        }
        // Get mrenclave on chain
        std::string code_on_chain = crust::Chain::get_instance()->get_swork_code();
        if (code_on_chain == "")
        {
            p_log->err("Get sworker code from chain failed! Please check the running status of the chain.\n");
            return CRUST_UNEXPECTED_ERROR;
        }
        // Compare these two mrenclave
        if (code_on_chain.compare(id_info["mrenclave"].ToString()) != 0)
        {
            print_attention();
            std::string cmd1(HRED "sudo crust tools upgrade-image sworker && sudo crust reload sworker" NC);
            p_log->err("Mrenclave is '%s', code on chain is '%s'. Your sworker need to upgrade, "
                    "please get the latest sworker by running '%s'\n",
                    id_info["mrenclave"].ToString().c_str(), code_on_chain.c_str(), cmd1.c_str());
            return CRUST_SWORKER_UPGRADE_NEEDED;
        }
        else
        {
            p_log->info("Mrenclave is '%s'\n", id_info["mrenclave"].ToString().c_str());
        }

        if (!crust::Chain::get_instance()->post_sworker_identity(sworker_identity))
        {
            p_log->err("Send identity to crust chain failed!\n");
            return CRUST_UNEXPECTED_ERROR;
        }
    }
    else
    {
        p_log->info("Send identity to crust chain successfully!\n");
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Store enclave id information
 * @param info (in) -> Pointer to enclave id information
 */
void ocall_store_enclave_id_info(const char *info)
{
    EnclaveData::get_instance()->set_enclave_id_info(info);
}

/**
 * @description: Store enclave workload
 * @param data (in) -> Workload information
 * @param data_size -> Workload size
 * @param cover -> Cover old data or not
 */
void ocall_store_workload(const char *data, size_t data_size, bool cover /*=true*/)
{
    if (cover)
    {
        EnclaveData::get_instance()->set_enclave_workload(std::string(data, data_size));
    }
    else
    {
        std::string str = EnclaveData::get_instance()->get_enclave_workload();
        str.append(data, data_size);
        EnclaveData::get_instance()->set_enclave_workload(str);
    }
}

/**
 * @description: Store upgrade data
 * @param data (in) -> Upgrade data
 * @param data_size -> Upgrade data size
 * @param cover -> Cover old upgrade data or not
 */
void ocall_store_upgrade_data(const char *data, size_t data_size, bool cover)
{
    if (cover)
    {
        EnclaveData::get_instance()->set_upgrade_data(std::string(data, data_size));
    }
    else
    {
        std::string str = EnclaveData::get_instance()->get_upgrade_data();
        str.append(data, data_size);
        EnclaveData::get_instance()->set_upgrade_data(str);
    }
}

/**
 * @description: Store unsealed data
 * @param unsealed_root (in) -> Unsealed data root
 * @param p_unsealed_data (in) -> Unsealed data
 * @param unsealed_data_len -> Unsealed data size
 */
void ocall_store_unsealed_data(const char *unsealed_root, uint8_t *p_unsealed_data, size_t unsealed_data_len)
{
    EnclaveData::get_instance()->add_unsealed_data(unsealed_root, p_unsealed_data, unsealed_data_len);
}

/**
 * @description: Get chain block information
 * @param data (in, out) -> Pointer to file block information
 * @param data_size -> Pointer to file block data size
 * @return: Get result
 */
crust_status_t ocall_chain_get_block_info(char *data, size_t /*data_size*/)
{
    crust::BlockHeader block_header;
    if (!crust::Chain::get_instance()->get_block_header(block_header))
    {
        return CRUST_UNEXPECTED_ERROR;
    }

    json::JSON bh_json;
    bh_json[CHAIN_BLOCK_NUMBER] = block_header.number;
    bh_json[CHAIN_BLOCK_HASH] = block_header.hash;

    std::string bh_str = bh_json.dump();
    remove_char(bh_str, '\n');
    remove_char(bh_str, '\\');
    remove_char(bh_str, ' ');

    memcpy(data, bh_str.c_str(), bh_str.size());

    return CRUST_SUCCESS;
}

/**
 * @description: Store file information
 * @param cid (in) -> File content identity
 * @param data (in) -> File information data
 */
void ocall_store_file_info(const char* cid, const char *data)
{
    EnclaveData::get_instance()->add_sealed_file_info(cid, data);
}

/**
 * @description: Store all file information
 * @param data -> All file information
 * @param data_size -> All file information size
 */
void ocall_store_file_info_all(const uint8_t *data, size_t data_size)
{
    EnclaveData::get_instance()->restore_sealed_file_info(data, data_size);
}

/**
 * @description: Recall validate meaningful files
 */
void ocall_recall_validate_file()
{
    Validator::get_instance()->validate_file();
}

/**
 * @description: Recall validate srd
 */
void ocall_recall_validate_srd()
{
    Validator::get_instance()->validate_srd();
}
