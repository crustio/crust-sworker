#include "Log.h"

std::mutex log_mutex;

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
        log_mutex.lock();
        if(Log::log == NULL)
        {
            Log::log = new Log();
        }
        log_mutex.unlock(); 
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
    log_mutex.lock();
    va_list va;
    va_start(va, format);
    int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
    va_end(va);
    std::string log_str(this->log_buf, n);
    this->base_log(log_str, CRUST_LOG_INFO_TAG);
    log_mutex.unlock();
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::warn(const char *format, ...)
{
    log_mutex.lock();
    va_list va;
    va_start(va, format);
    int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
    va_end(va);
    std::string log_str(this->log_buf, n);
    this->base_log(log_str, CRUST_LOG_WARN_TAG);
    log_mutex.unlock();
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::err(const char *format, ...)
{
    log_mutex.lock();
    va_list va;
    va_start(va, format);
    int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
    va_end(va);
    std::string log_str(this->log_buf, n);
    this->base_log(log_str, CRUST_LOG_ERR_TAG);
    log_mutex.unlock();
}

/**
 * @description: print information
 * @param format -> data format 
 * */
void Log::debug(const char *format, ...)
{
    if (this->debug_flag)
    {
        log_mutex.lock();
        va_list va;
        va_start(va, format);
        int n = vsnprintf(this->log_buf, CRUST_LOG_BUF_SIZE, format, va);
        va_end(va);
        std::string log_str(this->log_buf, n);
        this->base_log(log_str, CRUST_LOG_DEBUG_TAG);
        log_mutex.unlock();
    }
}

/**
 * @description: print base data
 * @param log_str -> data for logging
 * @param tag -> log tag
 * */
void Log::base_log(std::string log_str, std::string tag)
{
    // Get timestamp
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);

    int milli_sec = cur_time.tv_usec / 1000;
    char time_str[64];

    // If you change this format, you may need to change the size of time_str
    if (strftime(time_str, 64,  "%b %e %Y %T", localtime(&cur_time.tv_sec)) == 0)
    {
        time_str[0] = 0;
    }
    
     printf("[%s.%03d] [%s] %s", time_str, milli_sec, tag.c_str(), log_str.c_str());

     fflush(stdout);
}

} // namespace crust
