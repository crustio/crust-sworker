#include "Chain.h"
#include "Config.h"

Chain *chain = NULL;
crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: new a global chain handler to access chain node
 * @param url -> chain API base url
 * @param password -> the password of chain account id
 * @param backup ->  the backup of chain account id
 * @return: the point of chain handler
 */
Chain *new_chain(std::string url, std::string password, std::string backup)
{
    if (chain != NULL)
    {
        delete chain;
    }

    chain = new Chain(url, password, backup);
    return chain;
}

/**
 * @description: get the global chain handler to access chain node 
 * @return: the point of chain handle
 */
Chain *get_chain(void)
{
    if (chain == NULL)
    {
        p_log->info("Create chain instance!\n");
        Config *p_config = Config::get_instance();
        if (p_config == NULL)
        {
            p_log->err("Get configure failed!\n");
            return NULL;
        }
        chain = new Chain(p_config->crust_api_base_url, p_config->crust_password, p_config->crust_backup);
    }

    return chain;
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

        return NULL;
    }
    catch (const std::exception &e)
    {
        p_log->err("HTTP throw: %s\n", e.what());
    }

    return NULL;
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

        return false;
    }
    catch (const std::exception &e)
    {
        p_log->err("HTTP throw: %s\n", e.what());
    }

    return false;
}

/**
 * @description: post tee identity to chain chain
 * @param identity -> tee identity
 * @return: success or fail
 * */
bool Chain::post_tee_identity(std::string identity)
{
    try
    {
        std::string path = this->url_end_point->base + "/tee/identity";
        httplib::Headers headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj;
        obj["identity"] = identity;
        obj["backup"] = this->backup;
        auto res = this->chain_client->Post(path.c_str(), headers, obj.dump(), "application/json");

        if (res && res->status == 200)
        {
            return true;
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
 * @description: post tee work report to chain
 * @param work_report -> tee work report
 * @return: success or fail
 * */
bool Chain::post_tee_work_report(std::string work_report)
{
    try
    {
        std::string path = this->url_end_point->base + "/tee/workreport";
        httplib::Headers headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj;
        obj["workreport"] = work_report;
        obj["backup"] = this->backup;
        auto res = this->chain_client->Post(path.c_str(), headers, obj.dump(), "application/json");

        if (res && res->status == 200)
        {
            return true;
        }

        return false;
    }
    catch (const std::exception &e)
    {
        p_log->err("HTTP throw: %s\n", e.what());
    }

    return false;
}
