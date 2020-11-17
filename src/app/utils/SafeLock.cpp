#include "SafeLock.h"

SafeLock::~SafeLock()
{
    if (this->lock_time > 0)
    {
        this->_mutex.unlock();
    }
}

void SafeLock::lock()
{
    if (this->lock_time == 0)
    {
        this->_mutex.lock();
        this->lock_time++;
    }
}

void SafeLock::unlock()
{
    if (this->lock_time > 0)
    {
        this->lock_time--;
        this->_mutex.unlock();
    }
}
