#ifndef _CRUST_DATABASE_H_
#define _CRUST_DATABASE_H_

#include "leveldb/db.h"
#include "CrustStatus.h"

namespace crust
{

class DataBase
{
public:
    static DataBase *get_instance();
    crust_status_t add(std::string key, std::string value);
    crust_status_t del(std::string key);
    crust_status_t set(std::string key, std::string value);
    crust_status_t get(std::string key, std::string &value);
    static DataBase *database;

private:
    DataBase() {}
    DataBase(const DataBase &);
    DataBase& operator = (const DataBase &);
    leveldb::DB *db;
    leveldb::WriteOptions write_opt;
};

} // namespace crust

#endif /* !_CRUST_DATABASE_H_ */
