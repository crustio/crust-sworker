#ifndef _CRUST_DEFER_H_
#define _CRUST_DEFER_H_

#include <functional>

class Defer
{
public:
    Defer(std::function<void()> f): _f(f) {}
    ~Defer() { this->_f(); }

private:
    std::function<void()> _f;
};

#endif /* !_CRUST_DEFER_H_ */
