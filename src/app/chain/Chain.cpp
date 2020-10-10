#include "Chain.h"
#include "HttpClient.h"

crust::Log *p_log = crust::Log::get_instance();
HttpClient *pri_chain_client = NULL;

namespace crust
{

Chain *Chain::chain = NULL;

/**
 * @desination: single instance class function to get instance
 * @return: chain instance
 */
Chain *Chain::get_instance()
{
    if (Chain::chain == NULL)
    {
        Config *p_config = Config::get_instance();
        Chain::chain = new Chain(p_config->chain_api_base_url, p_config->chain_password, p_config->chain_backup);
    }

    return Chain::chain;
}

/**
 * @description: new a chain handler to access chain node
 * @param url -> chain API base url, like: http://127.0.0.1:56666/api/v1
 * @param password_tmp -> the password of chain account id
 * @param backup_tmp ->  the backup of chain account id
 */
Chain::Chain(std::string url, std::string password_tmp, std::string backup_tmp)
{
    this->url = url;
    this->url_end_point = get_url_end_point(url);
    this->password = password_tmp;
    this->backup = backup_tmp;
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
 * @return: the point of block header
 */
BlockHeader *Chain::get_block_header(void)
{
    std::string path = this->url + "/block/header";
    http::response<http::string_body> res = pri_chain_client->Get(path.c_str());
    if ((int)res.result() == 200)
    {
        json::JSON block_header_json = json::JSON::Load(res.body());
        BlockHeader *block_header = new BlockHeader();
        block_header->hash = block_header_json["hash"].ToString().erase(0,2);
        block_header->number = block_header_json["number"].ToInt();
        return block_header;
    }

    if (res.body().size() != 0)
    {
        p_log->err("%s\n", res.body().c_str());
    }
    else
    {
        p_log->err("%s\n", "return body is null");
    }

    return NULL;
}


/**
 * @description: get block hash by number
 * @param block_number block number
 * @return: block hash
 */
std::string Chain::get_block_hash(size_t block_number)
{
    std::string url = this->url + "/block/hash?blockNumber=" + std::to_string(block_number);
    http::response<http::string_body> res = pri_chain_client->Get(url.c_str());
    if ((int)res.result() == 200)
    {
        return res.body().substr(3, 64);
    }

    if (res.body().size() != 0)
    {
        p_log->debug("%s\n", res.body().c_str());
    }
    else
    {
        p_log->err("%s\n", "return body is null");
    }

    return "";
}

/**
 * @description: test if chian is online
 * @return: test result
 */
bool Chain::is_online(void)
{
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
    std::string path = this->url + "/system/health";
    http::response<http::string_body> res = pri_chain_client->Get(path.c_str());
    if ((int)res.result() == 200)
    {
        json::JSON system_health_json = json::JSON::Load(res.body());
        return system_health_json["isSyncing"].ToBool();
    }

    if (res.body().size() != 0)
    {
        p_log->err("%s\n", res.body().c_str());
    }
    else
    {
        p_log->err("%s\n", "return body is null");
    }

    return true;
}

/**
 * @description: waiting for the crust chain to run
 * @return: success or not
 */
bool Chain::wait_for_running(void)
{
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
        crust::BlockHeader *block_header = this->get_block_header();
        if (block_header->number >= start_block_height)
        {
            break;
        }
        else
        {
            p_log->info("Wait for the chain to execute after %lu blocks, now is %lu ...\n", start_block_height, block_header->number);
            sleep(3);
        }
    }

    while (true)
    {
        if (!this->is_syncing())
        {
            break;
        }
        else
        {
            crust::BlockHeader *block_header = this->get_block_header();
            p_log->info("Wait for chain synchronization to complete, currently synchronized to the %lu block\n", block_header->number);
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
bool Chain::post_sworker_identity(std::string identity)
{
    for(int i = 0; i < 3; i++)
    {
        std::string path = this->url + "/swork/identity";
        ApiHeaders headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj = json::JSON::Load(identity);
        obj["backup"] = this->backup;
        http::response<http::string_body> res = pri_chain_client->Post(path.c_str(), obj.dump(), "application/json", headers);

        if ((int)res.result() == 200)
        {
            return true;
        }

        if (res.body().size() != 0)
        {
            p_log->err("%s\n", res.body().c_str());
        }
        else
        {
            p_log->err("%s\n", "return body is null");
        }

        usleep(3000000);
    }

    return false;
}

/**
 * @description: post swork work report to chain
 * @param work_report -> swork work report
 * @return: success or fail
 */
bool Chain::post_sworker_work_report(std::string work_report)
{
    for(int i = 0; i < 3; i++)
    {
        std::string path = this->url + "/swork/workreport";
        ApiHeaders headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj = json::JSON::Load(work_report);
        obj["backup"] = this->backup;
        http::response<http::string_body> res = pri_chain_client->Post(path.c_str(), obj.dump(), "application/json", headers);

        if ((int)res.result() == 200)
        {
            return true;
        }

        if (res.body().size() != 0)
        {
            p_log->err("%s\n", res.body().c_str());
        }
        else
        {
            p_log->err("%s\n", "return body is null");
        }
        
        usleep(3000000);
    }

    return false;
}

} // namespace crust
