#include "DataBase.h"
#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include "Config.h"
#include "Log.h"

DataBase* DataBase::database = NULL;
crust::Log *p_log = crust::Log::get_instance();

DataBase *DataBase::get_instance()
{
    if (database == NULL)
    {
        database = new DataBase();

        leveldb::Options options;
        options.create_if_missing = true;
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

crust_status_t DataBase::add(std::string key, std::string value)
{
    leveldb::Status s = this->db->Put(this->write_opt, key, value);
    if (!s.ok())
    {
        p_log->warn("Insert record to DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_ADD_FAILED;
    }

    return CRUST_SUCCESS;
}

crust_status_t DataBase::del(std::string key)
{
    leveldb::WriteBatch batch;
    batch.Delete(key);
    leveldb::Status s = this->db->Write(this->write_opt, &batch);
    if (!s.ok())
    {
        p_log->warn("Delete record from DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_DEL_FAILED;
    }

    return CRUST_SUCCESS;
}

crust_status_t DataBase::set(std::string key, std::string value)
{
    leveldb::Status s = this->db->Put(this->write_opt, key, value);
    if (!s.ok())
    {
        p_log->warn("Update record from DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_SET_FAILED;
    }

    return CRUST_SUCCESS;
}

crust_status_t DataBase::get(std::string key, std::string &value)
{
    leveldb::Status s = this->db->Get(leveldb::ReadOptions(), key, &value);
    if (!s.ok())
    {
        p_log->warn("Get record from DB failed!Error: %s\n", s.ToString().c_str());
        return CRUST_PERSIST_GET_FAILED;
    }

    return CRUST_SUCCESS;
}
