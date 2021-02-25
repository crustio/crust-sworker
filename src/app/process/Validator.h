#ifndef _APP_VALIDATOR_H_
#define _APP_VALIDATOR_H_

#include <vector>

#include "Config.h"
#include "Ctpl.h"

#define VALIDATE_MAX_THREAD_NUM 8

class Validator
{
public:
    static Validator *get_instance();
    void validate_file();
    void validate_srd();

private:
    Validator();
    static Validator *validator;
    ctpl::thread_pool *validate_pool;
    std::vector<std::shared_ptr<std::future<void>>> validate_tasks_v;
};

#endif /* ! _APP_VALIDATOR_H_ */
