#include "Chain.h"

crust::Log *p_log = crust::Log::get_instance();
HttpClient *pri_chain_client = NULL;
extern bool offline_chain_mode;

namespace crust
{

Chain *Chain::chain = NULL;
std::mutex chain_mutex;

/**
 * @description: single instance class function to get instance
 * @return: chain instance
 */
Chain *Chain::get_instance()
{
    if (Chain::chain == NULL)
    {
        Config *p_config = Config::get_instance();
        chain_mutex.lock();
        if (Chain::chain == NULL)
        {
            Chain::chain = new Chain(p_config->chain_api_base_url, p_config->chain_password, p_config->chain_backup, offline_chain_mode);
        }
        chain_mutex.unlock();
    }

    return Chain::chain;
}

/**
 * @description: new a chain handler to access chain node
 * @param url -> chain API base url, like: http://127.0.0.1:56666/api/v1
 * @param password_tmp -> the password of chain account id
 * @param backup_tmp ->  the backup of chain account id
 * @param is_offline -> Off chain mode or not
 */
Chain::Chain(std::string url, std::string password_tmp, std::string backup_tmp, bool is_offline)
{
    this->url = url;
    this->password = password_tmp;
    this->backup = backup_tmp;
    this->is_offline = is_offline;
    this->offline_block_height = 0;
    pri_chain_client = new HttpClient();
}

/**
 * @description: destructor
 */
Chain::~Chain()
{
    if (pri_chain_client != NULL)
    {
        delete pri_chain_client;
        pri_chain_client = NULL;
    }
}

/**
 * @description: get laster block header from chain
 * @param block_header -> Reference to block_header
 * @return: the point of block header
 */
bool Chain::get_block_header(BlockHeader &block_header)
{
    if (this->is_offline)
    {
        offline_block_height_mutex.lock();
        if (this->offline_block_height == 0)
        {
            this->offline_block_height = this->get_offline_block_height();
        }
        block_header.number = this->offline_block_height;
        offline_block_height_mutex.unlock();

        block_header.hash = "1000000000000000000000000000000000000000000000000000000000000001";
        return true;
    }

    std::string path = this->url + "/block/header";
    http::response<http::string_body> res = pri_chain_client->Get(path.c_str());
    if ((int)res.result() == 200)
    {
        json::JSON block_header_json = json::JSON::Load_unsafe(res.body());
        block_header.hash = block_header_json["hash"].ToString().erase(0,2);
        block_header.number = block_header_json["number"].ToInt();
        return true;
    }

    if (res.body().size() != 0)
    {
        p_log->err("%s\n", res.body().c_str());
    }
    else
    {
        p_log->err("%s\n", "Get block header:return body is null");
    }

    return false;
}


/**
 * @description: get block hash by number
 * @param block_number block number
 * @return: block hash
 */
std::string Chain::get_block_hash(size_t block_number)
{
    if (this->is_offline)
    {
        return "1000000000000000000000000000000000000000000000000000000000000001";
    }

    std::string url = this->url + "/block/hash?blockNumber=" + std::to_string(block_number);
    http::response<http::string_body> res = pri_chain_client->Get(url.c_str());
    std::string res_body = res.body();
    if ((int)res.result() == 200)
    {
        if (res_body.size() > 3)
        {
            return res_body.substr(3, 64);
        }
    }

    if (res_body.size() != 0)
    {
        p_log->info("%s\n", res_body.c_str());
    }
    else
    {
        p_log->err("%s\n", "Get block hash:return body is null");
    }

    return "";
}


/**
 * @description: get block hash by number
 * @return: swork code on chain
 */
std::string Chain::get_swork_code()
{
    if (this->is_offline)
    {
        return "04579f4102301d39f68032446b63fc0cede4817cf099312a0c397a760651af98";
    }

    std::string url = this->url + "/swork/code";
    http::response<http::string_body> res = pri_chain_client->Get(url.c_str());
    std::string res_body = res.body();
    if ((int)res.result() == 200)
    {
        if (res_body.size() > 3)
        {
            return res_body.substr(3, 64);
        }
    }

    if (res_body.size() != 0)
    {
        p_log->info("%s\n", res_body.c_str());
    }
    else
    {
        p_log->err("%s\n", "Get swork code:return body is null");
    }

    return "";
}

/**
 * @description: test if chian is online
 * @return: test result
 */
bool Chain::is_online(void)
{
    if (this->is_offline)
    {
        return true;
    }

    std::string path = this->url + "/block/header";
    http::response<http::string_body> res = pri_chain_client->Get(path.c_str());
    if ((int)res.result() == 200)
    {
        return true;
    }

    return false;
}

/**
 * @description: test if chian is syncing
 * @return: test result
 */
bool Chain::is_syncing(void)
{
    if (this->is_offline)
    {
        return false;
    }

    std::string path = this->url + "/system/health";
    http::response<http::string_body> res = pri_chain_client->Get(path.c_str());
    if ((int)res.result() == 200)
    {
        json::JSON system_health_json = json::JSON::Load_unsafe(res.body());
        return system_health_json["isSyncing"].ToBool();
    }

    if (res.body().size() != 0)
    {
        p_log->err("%s\n", res.body().c_str());
    }
    else
    {
        p_log->err("%s\n", "Is syncing:return body is null");
    }

    return true;
}

/**
 * @description: waiting for the crust chain to run
 * @return: success or not
 */
bool Chain::wait_for_running(void)
{
    if (this->is_offline)
    {
        return true;
    }

    size_t start_block_height = 10;

    while (true)
    {
        if (this->is_online())
        {
            break;
        }
        else
        {
            p_log->info("Waiting for chain to run...\n");
            sleep(3);
        }
    }

    while (true)
    {
        crust::BlockHeader block_header;
        if (!this->get_block_header(block_header))
        {
            p_log->info("Waiting for chain to run...\n");
            sleep(3);
            continue;
        }

        if (block_header.number >= start_block_height)
        {
            break;
        }
        else
        {
            p_log->info("Wait for the chain to execute after %lu blocks, now is %lu ...\n", start_block_height, block_header.number);
            sleep(3);
        }
    }

    while (true)
    {
        if (!this->is_syncing() && !this->is_syncing())
        {
            break;
        }
        else
        {
            crust::BlockHeader block_header;
            if (this->get_block_header(block_header))
            {
                p_log->info("Wait for chain synchronization to complete, currently synchronized to the %lu block\n", block_header.number);
            }
            else
            {
                p_log->info("Waiting for chain to run...\n");
            }
            sleep(6);
        }   
    }

    return true;
}

/**
 * @description: post sworker identity to chain chain
 * @param identity -> sworker identity
 * @return: success or fail
 */
bool Chain::post_epid_identity(std::string identity)
{
    if (this->is_offline)
    {
        return true;
    }

    for (int i = 0; i < 20; i++)
    {
        std::string path = this->url + "/swork/identity";
        ApiHeaders headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        crust_status_t crust_status = CRUST_SUCCESS;
        json::JSON obj = json::JSON::Load(&crust_status, identity);
        if (CRUST_SUCCESS != crust_status)
        {
            p_log->err("Parse sworker identity failed! Error code:%lx\n", crust_status);
            return false;
        }
        obj["backup"] = this->backup;
        http::response<http::string_body> res = pri_chain_client->Post(path.c_str(), obj.dump(), "application/json", headers);

        if ((int)res.result() == 200)
        {
            return true;
        }

        if (res.body().size() != 0)
        {
            p_log->err("Chain result: %s, wait 10s and try again\n", res.body().c_str());
        }
        else
        {
            p_log->err("Chain result: %s, wait 10s and try again\n", "upload identity:return body is null");
        }

        sleep(10);
    }

    return false;
}

/**
 * @description: post sworker quote to registry chain
 * @param quote -> sworker quote
 * @return: success or fail
 */
bool Chain::post_ecdsa_quote(std::string quote)
{
    if (this->is_offline)
    {
        return true;
    }

    p_log->info("id:%s\n", quote.c_str());
    int wait_time = 10;
    for (int i = 0; i < 20; i++)
    {
        std::string path = this->url + "/verifier/requestVerification";
        ApiHeaders headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj;
        obj["backup"] = this->backup;
        obj["evidence"] = quote;
        http::response<http::string_body> res = pri_chain_client->Post(path.c_str(), obj.dump(), "application/json", headers);

        if ((int)res.result() == 200)
        {
            return true;
        }

        if (res.body().size() != 0)
        {
            p_log->err("Chain result: %s, wait %ds and try again\n", res.body().c_str(), wait_time);
        }
        else
        {
            p_log->err("Chain result: return body is null, wait %ds and try again\n", wait_time);
        }

        sleep(wait_time);
    }

    return false;
}

/**
 * @description: Post sworker identity to crust chain
 * @param identity -> sworker identity
 * @return: success or fail
 */
bool Chain::post_ecdsa_identity(const std::string identity)
{
    if (this->is_offline)
    {
        return true;
    }

    p_log->debug("identity:%s\n", identity.c_str());
    int wait_time = 10;
    for (int i = 0; i < 20; i++)
    {
        std::string path = this->url + "/swork/registerWithDeauthChain";
        ApiHeaders headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        crust_status_t crust_status = CRUST_SUCCESS;
        json::JSON obj = json::JSON::Load(&crust_status, identity);
        if (CRUST_SUCCESS != crust_status)
        {
            p_log->err("Parse sworker identity failed! Error code:%lx\n", crust_status);
            return false;
        }
        obj["backup"] = this->backup;
        http::response<http::string_body> res = pri_chain_client->Post(path.c_str(), obj.dump(), "application/json", headers);

        if ((int)res.result() == 200)
        {
            return true;
        }

        if (res.body().size() != 0)
        {
            p_log->err("Chain result: %s, wait %ds and try again\n", res.body().c_str(), wait_time);
        }
        else
        {
            p_log->err("Chain result: return body is null, wait %ds and try again\n", wait_time);
        }

        sleep(wait_time);
    }

    return false;
}

/**
 * @description: Get verification report from registry chain
 * @return: Verification report
 */
std::string Chain::get_ecdsa_verify_result()
{
    if (this->is_offline)
        return "";

    std::string id_info = EnclaveData::get_instance()->get_enclave_id_info();
    crust_status_t crust_status = CRUST_SUCCESS;
    json::JSON id_info_json = json::JSON::Load(&crust_status, id_info);
    if (CRUST_SUCCESS != crust_status)
    {
        p_log->err("Get verification result failed due to get id info failed, error code:%lx\n", crust_status);
        return "";
    }

    int wait_time = 30;
    for (int i = 0; i < 20; i++)
    {
        std::string path = this->url 
            + "/verifier/verificationResults?address=" + Config::get_instance()->chain_address
            + "&pubKey=" + id_info_json["pub_key"].ToString();
        http::response<http::string_body> res = pri_chain_client->Get(path.c_str());

        if ((int)res.result() == 200)
        {
            return res.body();
        }

        if (res.body().size() != 0)
        {
            p_log->err("Chain result: %s, wait %ds and try again\n", res.body().c_str(), wait_time);
        }
        else
        {
            p_log->err("Chain result: return body is null, wait %ds and try again\n", wait_time);
        }

        sleep(wait_time);
    }

    return "";
}

/**
 * @description: post sworker work report to chain
 * @param work_report -> sworker work report
 * @return: success or fail
 */
bool Chain::post_sworker_work_report(std::string work_report)
{
    if (this->is_offline)
    {
        return true;
    }

    for (int i = 0; i < 20; i++)
    {
        std::string path = this->url + "/swork/workreport";
        ApiHeaders headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        crust_status_t crust_status = CRUST_SUCCESS;
        json::JSON obj = json::JSON::Load(&crust_status, work_report);
        if (CRUST_SUCCESS != crust_status)
        {
            p_log->err("Parse sworker workreport failed! Error code:%lx\n", crust_status);
            return false;
        }
        obj["backup"] = this->backup;
        http::response<http::string_body> res = pri_chain_client->Post(path.c_str(), obj.dump(), "application/json", headers);

        if ((int)res.result() == 200)
        {
            return true;
        }

        if (res.body().size() != 0)
        {
            json::JSON res_json = json::JSON::Load_unsafe(res.body());
            std::string msg = res_json["message"].ToString();
            if (msg == "swork.InvalidReportTime")
            {
                p_log->err("Chain error: %s. Please check the synchronization of the chain!\n", res.body().c_str());
                return false;
            } 
            else if (msg == "swork.IllegalReporter")
            {
                p_log->err("Chain error: %s. The current account does not match the original account, please stop sworker and reconfigure! SF:WRE\n", res.body().c_str());
                return false;
            }
            else if (msg == "swork.OutdatedReporter")
            {
                p_log->err("Chain error: %s. The current sworker has expired, please shovel the data and run a new sworker! SF:WRE\n", res.body().c_str());
                return false;
            }
            else if (msg == "swork.IllegalWorkReportSig" || msg == "swork.IllegalFilesTransition" || msg == "swork.ABUpgradeFailed")
            {
                p_log->err("Chain error: %s SF:WRE\n", res.body().c_str());
                return false;
            }
            else
            {
                p_log->err("Chain error: %s, wait 10s and try again. SF:WRE\n", res.body().c_str());
            }
        }
        else
        {
            p_log->err("Chain result: %s, wait 10s and try again. SF:WRE\n", "upload workreport:return body is null");
        }
        
        sleep(10);
    }

    return false;
}

size_t Chain::get_offline_block_height(void)
{
    std::string offline_base_height_str = "";
    if (crust::DataBase::get_instance()->get("offline_block_height_key", offline_base_height_str) == CRUST_SUCCESS)
    {
        std::stringstream sstream(offline_base_height_str);
        size_t h = 0;
        sstream >> h;
        return h;
    }
    return 0;
}

void Chain::add_offline_block_height(size_t h)
{
    offline_block_height_mutex.lock();
    crust::DataBase::get_instance()->set("offline_block_height_key", std::to_string(this->offline_block_height + h));
    this->offline_block_height += h;
    offline_block_height_mutex.unlock();
}

} // namespace crust
