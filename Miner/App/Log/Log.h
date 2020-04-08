#ifndef _CRUST_LOG_H_
#define _CRUST_LOG_H_

#include <stdio.h>

namespace crust
{

class Log
{
public:
    static Log *log;
    static Log *get_instance();
    void open_debug(void);

private:
    bool debug;
    Log(void);
};

} // namespace crust

#endif /* !_CRUST_LOG_H_ */
