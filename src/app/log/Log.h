#ifndef _CRUST_LOG_H_
#define _CRUST_LOG_H_

#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <string>
#include <mutex>

#include "Resource.h"

#define CRUST_LOG_BUF_SIZE  33554432 /* 32*1024*1024 */
#define CRUST_LOG_INFO_TAG "INFO"
#define CRUST_LOG_WARN_TAG "WARN"
#define CRUST_LOG_ERR_TAG "ERROR"
#define CRUST_LOG_DEBUG_TAG "DEBUG"

namespace crust
{

class Log
{
public:
    static Log *log;
    static Log *get_instance();
    void set_debug(bool flag);
    void info(const char *format, ...);
    void warn(const char *format, ...);
    void err(const char *format, ...);
    void debug(const char *format, ...);
    bool get_debug_flag();

private:
    void base_log(std::string log_data, std::string tag);
    bool debug_flag;
    char log_buf[CRUST_LOG_BUF_SIZE];
    Log(void);
};

} // namespace crust

#endif /* !_CRUST_LOG_H_ */
