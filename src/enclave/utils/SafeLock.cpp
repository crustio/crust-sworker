#include "SafeLock.h"

SafeLock::~SafeLock()
{
    if (this->lock_time > 0)
    {
        sgx_thread_mutex_unlock(&this->_mutex);
    }
}

void SafeLock::lock()
{
    if (this->lock_time == 0)
    {
        sgx_thread_mutex_lock(&this->_mutex);
        this->lock_time++;
    }
}

void SafeLock::unlock()
{
    if (this->lock_time > 0)
    {
        this->lock_time--;
        sgx_thread_mutex_unlock(&this->_mutex);
    }
}
