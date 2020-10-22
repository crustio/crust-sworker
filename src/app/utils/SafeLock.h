#ifndef _CRUST_SAFELOCK_H_
#define _CRUST_SAFELOCK_H_

#include <mutex>

class SafeLock
{
public:
    SafeLock(std::mutex &mutex): _mutex(mutex), lock_time(0) {}
    ~SafeLock();
    void lock();
    void unlock();

private:
    std::mutex &_mutex;
    int lock_time;
};


#endif /* !_CRUST_SAFELOCK_H_ */
