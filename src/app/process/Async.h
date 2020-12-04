#ifndef _APP_ASYNC_H_
#define _APP_ASYNC_H_

#include <string>
#include <future>
#include "Log.h"
#include "Chain.h"


#if defined(__cplusplus)
extern "C"
{
#endif

void async_storage_delete(std::string cid);

void async_storage_seal(std::string cid);

#if defined(__cplusplus)
}
#endif

#endif /* ! _APP_ASYNC_H_ */
