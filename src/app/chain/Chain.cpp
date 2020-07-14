#include "Chain.h"

crust::Log *p_log = crust::Log::get_instance();

namespace crust
{

Chain *Chain::chain = NULL;

/**
 * @desination: single instance class function to get instance
 * @return: chain instance
 * */
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
    this->url_end_point = get_url_end_point(url);
    this->chain_client = new httplib::Client(this->url_end_point->ip, this->url_end_point->port);
    this->password = password_tmp;
    this->backup = backup_tmp;
}

/**
 * @description: destructor
 */
Chain::~Chain()
{
    delete this->chain_client;
}

/**
 * @description: get laster block header from chain
 * @return: the point of block header
 */
BlockHeader *Chain::get_block_header(void)
{
    try
    {
        std::string path = this->url_end_point->base + "/block/header";
        auto res = this->chain_client->Get(path.c_str());
        if (res && res->status == 200)
        {
            json::JSON block_header_json = json::JSON::Load(res->body);

            BlockHeader *block_header = new BlockHeader();
            block_header->hash = block_header_json["hash"].ToString().erase(0,2);
            block_header->number = block_header_json["number"].ToInt();
            return block_header;
        }
        else if (res)
        {
            p_log->err("%s\n", res->body.c_str());
        }

        return NULL;
    }
    catch (const std::exception &e)
    {
        p_log->err("HTTP throw: %s\n", e.what());
    }

    return NULL;
}


/**
 * @description: get block hash by number
 * @param block_number block number
 * @return: block hash
 * */
std::string Chain::get_block_hash(size_t block_number)
{
    try
    {
        std::string url = this->url_end_point->base + "/block/hash?blockNumber=" + std::to_string(block_number);
        auto res = this->chain_client->Get(url.c_str());
        if (res && res->status == 200)
        {
            return res->body.substr(3, 64);
        }
        else if (res)
        {
            p_log->err("%s\n", res->body.c_str());
        }

        return "";
    }
    catch (const std::exception &e)
    {
        p_log->err("HTTP throw: %s\n", e.what());
    }

    return "";
}


/**
 * @description: test if chian is online
 * @return: test result
 * */
bool Chain::is_online(void)
{
    try
    {
        std::string path = this->url_end_point->base + "/block/header";
        auto res = this->chain_client->Get(path.c_str());
        if (res && res->status == 200)
        {
            return true;
        }
        else if (res)
        {
            p_log->err("%s\n", res->body.c_str());
        }

        return false;
    }
    catch (const std::exception &e)
    {
        p_log->err("HTTP throw: %s\n", e.what());
    }

    return false;
}

/**
 * @description: waiting for the crust chain to run
 * @return: success or not
 * */
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

    return true;
}

/**
 * @description: post tee identity to chain chain
 * @param identity -> tee identity
 * @return: success or fail
 * */
bool Chain::post_tee_identity(std::string identity)
{
    for(int i = 0; i < 3; i++)
    {
        try
        {
            std::string path = this->url_end_point->base + "/tee/identity";
            httplib::Headers headers = {{"password", this->password}, {"Content-Type", "application/json"}};

            json::JSON obj = json::JSON::Load(identity);
            obj["backup"] = this->backup;
            auto res = this->chain_client->Post(path.c_str(), headers, obj.dump(), "application/json");

            if (res && res->status == 200)
            {
                return true;
            }
            else if (res)
            {
                p_log->err("%s\n", res->body.c_str());
            }

            return false;
        }
        catch (const std::exception &e)
        {
            p_log->err("HTTP throw: %s\n", e.what());
        }
    }

    return false;
}

/**
 * @description: post tee work report to chain
 * @param work_report -> tee work report
 * @return: success or fail
 * */
bool Chain::post_tee_work_report(std::string work_report)
{
    for(int i = 0; i < 3; i++)
    {
        try
        {
            std::string path = this->url_end_point->base + "/tee/workreport";
            httplib::Headers headers = {{"password", this->password}, {"Content-Type", "application/json"}};

            json::JSON obj = json::JSON::Load(work_report);
            obj["backup"] = this->backup;
            auto res = this->chain_client->Post(path.c_str(), headers, obj.dump(), "application/json");

            if (res && res->status == 200)
            {
                return true;
            }
            else if (res)
            {
                p_log->err("%s\n", res->body.c_str());
            }

            return false;
        }
        catch (const std::exception &e)
        {
            p_log->err("HTTP throw: %s\n", e.what());
        }
    }

    return false;
}

} // namespace crust
