#include "Log.h"

namespace crust
{

Log *Log::log = NULL;

/**
 * @desination: single instance class function to get instance
 * @return: log instance
 * */
Log *Log::get_instance()
{
    if (Log::log == NULL)
    {
        Log::log = new Log();
    }

    return Log::log;
}

/**
 * @desination: constructor
 * */
Log::Log()
{
    this->debug_flag = false;
}

/**
 * @desination: open debug mode
 * */
void Log::open_debug(void)
{
    this->debug_flag = true;
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::info(const char *format, ...)
{
    this->log_mutex.lock();
    va_list va;
    va_start(va, format);
    int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
    va_end(va);
    std::string log_str(this->log_buf, n);
    this->log_mutex.unlock();
    this->base_log(log_str, CRUST_LOG_INFO_TAG);
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::warn(const char *format, ...)
{
    this->log_mutex.lock();
    va_list va;
    va_start(va, format);
    int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
    va_end(va);
    std::string log_str(this->log_buf, n);
    this->log_mutex.unlock();
    this->base_log(log_str, CRUST_LOG_WARN_TAG);
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::err(const char *format, ...)
{
    this->log_mutex.lock();
    va_list va;
    va_start(va, format);
    int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
    va_end(va);
    std::string log_str(this->log_buf, n);
    this->log_mutex.unlock();
    this->base_log(log_str, CRUST_LOG_ERR_TAG);
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::debug(const char *format, ...)
{
    if (this->debug_flag)
    {
        this->log_mutex.lock();
        va_list va;
        va_start(va, format);
        int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
        va_end(va);
        std::string log_str(this->log_buf, n);
        this->log_mutex.unlock();
        this->base_log(log_str, CRUST_LOG_DEBUG_TAG);
    }
}

/**
 * @description: print base data
 * @param log_str -> data for logging
 * @param tag -> log tag
 * */
void Log::base_log(std::string log_str, const char* tag)
{
    // Get timestamp
    time_t ts;
    struct tm time_tm, *time_tmp;
    char time_str[64];
    time(&ts);

    time_tmp = localtime(&ts);
    if (time_tmp == NULL)
    {
        perror("localtime");
        return;
    }
    time_tm = *time_tmp;

    // If you change this format, you may need to change the size of time_str
    if (strftime(time_str, 64, "%b %e %Y %T", &time_tm) == 0)
    {
        time_str[0] = 0;
    }

    printf("[%s] [%s] %s", time_str, tag, log_str.c_str());
}

} // namespace crust