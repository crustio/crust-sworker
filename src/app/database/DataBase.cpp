#include "DataBase.h"

crust::Log *p_log = crust::Log::get_instance();

namespace crust
{

DataBase* DataBase::database = NULL;

/**
 * @description: Get single class instance
 * @return: The instance
 */
DataBase *DataBase::get_instance()
{
    if (database == NULL)
    {
        database = new DataBase();

        leveldb::Options options;
        options.create_if_missing = true;
        if (!create_directory(Config::get_instance()->db_path))
        {
            return NULL;
        }
        leveldb::Status s = leveldb::DB::Open(options, Config::get_instance()->db_path.c_str(), &database->db);
        if (!s.ok())
        {
            p_log->err("Initialize database failed!Database path:%s\n", Config::get_instance()->db_path.c_str());
            return NULL;
        }
        database->write_opt.sync = true;
    }

    return database;
}

/**
 * @description: Close leveldb
 */
DataBase::~DataBase()
{
    if (this->db != NULL)
        delete this->db;
}

/**
 * @description: Add key value pair to db
 * @param key -> key
 * @param value -> value
 * @return: Add status
 */
crust_status_t DataBase::add(std::string key, std::string value)
{
    std::string old_val;
    leveldb::Status s = this->db->Get(leveldb::ReadOptions(), key, &old_val);
    if (old_val.compare("") != 0)
    {
        value.append(";").append(old_val);
    }
    s = this->db->Put(this->write_opt, key, value);
    if (!s.ok())
    {
        p_log->debug("Insert record to DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_ADD_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Delete key value pair
 * @param key -> key
 * @return: Delete status
 */
crust_status_t DataBase::del(std::string key)
{
    leveldb::WriteBatch batch;
    batch.Delete(key);
    leveldb::Status s = this->db->Write(this->write_opt, &batch);
    if (!s.ok())
    {
        p_log->debug("Delete record from DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_DEL_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Update key value pair
 * @param key -> key
 * @param value -> value
 * @return: Update status
 */
crust_status_t DataBase::set(std::string key, std::string value)
{
    leveldb::Status s = this->db->Put(this->write_opt, key, value);
    if (!s.ok())
    {
        p_log->debug("Update record from DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_SET_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Get value by key
 * @param key -> key
 * @param value -> Reference to value
 * @return: Get status
 */
crust_status_t DataBase::get(std::string key, std::string &value)
{
    leveldb::Status s = this->db->Get(leveldb::ReadOptions(), key, &value);
    if (!s.ok())
    {
        //p_log->debug("Get record from DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_GET_FAILED;
    }

    return CRUST_SUCCESS;
}

} // namespace crust
