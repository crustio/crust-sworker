#ifndef _CRUST_SAFELOCK_H_
#define _CRUST_SAFELOCK_H_

#include "sgx_thread.h"

class SafeLock
{
public:
    SafeLock(sgx_thread_mutex_t &mutex): _mutex(mutex), lock_time(0) {}
    ~SafeLock();
    void lock();
    void unlock();

private:
    sgx_thread_mutex_t &_mutex;
    int lock_time;
};


#endif /* !_CRUST_SAFELOCK_H_ */
