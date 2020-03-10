#include "Crust.h"
#include "Config.h"

Crust *crust = NULL;

extern FILE *felog;

/**
 * @description: new a global crust handler to access crust node
 * @param url -> crust API base url
 * @param password -> the password of chain account id
 * @param backup ->  the backup of chain account id
 * @return: the point of crust handler
 */
Crust *new_crust(std::string url, std::string password, std::string backup)
{
    if (crust != NULL)
    {
        delete crust;
    }

    crust = new Crust(url, password, backup);
    return crust;
}

/**
 * @description: get the global crust handler to access crust node 
 * @return: the point of crust handle
 */
Crust *get_crust(void)
{
    if (crust == NULL)
    {
        cprintf_info(felog, "Create crust instance!\n");
        Config *p_config = Config::get_instance();
        if (p_config == NULL)
        {
            cprintf_err(felog, "Get configure failed!\n");
            return NULL;
        }
        crust = new Crust(p_config->crust_api_base_url, p_config->crust_password, p_config->crust_backup);
    }

    return crust;
}

/**
 * @description: new a crust handler to access crust node
 * @param url -> crust API base url, like: http://127.0.0.1:56666/api/v1
 * @param password_tmp -> the password of chain account id
 * @param backup_tmp ->  the backup of chain account id
 */
Crust::Crust(std::string url, std::string password_tmp, std::string backup_tmp)
{
    this->url_end_point = get_url_end_point(url);
    this->crust_client = new httplib::Client(this->url_end_point->ip, this->url_end_point->port);
    this->password = password_tmp;
    this->backup = backup_tmp;
}

/**
 * @description: destructor
 */
Crust::~Crust()
{
    delete this->crust_client;
}

/**
 * @description: get laster block header from Crust
 * @return: the point of block header
 */
BlockHeader *Crust::get_block_header(void)
{
    try
    {
        std::string path = this->url_end_point->base + "/block/header";
        auto res = this->crust_client->Get(path.c_str());
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
        cprintf_err(felog, "HTTP throw: %s\n", e.what());
    }

    return NULL;
}

/**
 * @description: test if there is usable crust api
 * @return: test result
 * */
bool Crust::is_online(void)
{
    try
    {
        std::string path = this->url_end_point->base + "/block/header";
        auto res = this->crust_client->Get(path.c_str());
        if (res && res->status == 200)
        {
            return true;
        }

        return false;
    }
    catch (const std::exception &e)
    {
        cprintf_err(felog, "HTTP throw: %s\n", e.what());
    }

    return false;
}

/**
 * @description: post tee identity to crust chain
 * @param identity -> tee identity
 * @return: success or fail
 * */
bool Crust::post_tee_identity(std::string identity)
{
    try
    {
        std::string path = this->url_end_point->base + "/tee/identity";
        httplib::Headers headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj;
        obj["identity"] = identity;
        obj["backup"] = this->backup;
        auto res = this->crust_client->Post(path.c_str(), headers, obj.dump(), "application/json");

        if (res && res->status == 200)
        {
            return true;
        }

        return false;
    }
    catch (const std::exception &e)
    {
        cprintf_err(felog, "HTTP throw: %s\n", e.what());
    }

    return false;
}

/**
 * @description: post tee work report to crust chain
 * @param work_report -> tee work report
 * @return: success or fail
 * */
bool Crust::post_tee_work_report(std::string work_report)
{
    try
    {
        std::string path = this->url_end_point->base + "/tee/workreport";
        httplib::Headers headers = {{"password", this->password}, {"Content-Type", "application/json"}};

        json::JSON obj;
        obj["workreport"] = work_report;
        obj["backup"] = this->backup;
        auto res = this->crust_client->Post(path.c_str(), headers, obj.dump(), "application/json");

        if (res && res->status == 200)
        {
            return true;
        }

        return false;
    }
    catch (const std::exception &e)
    {
        cprintf_err(felog, "HTTP throw: %s\n", e.what());
    }

    return false;
}
