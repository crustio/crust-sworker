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
    this->debug = false;
}

/**
 * @desination: open debug mode
 * */
void Log::open_debug(void)
{
    this->debug = true;
}

}