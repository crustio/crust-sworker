#ifndef _APP_STORAGE_H_
#define _APP_STORAGE_H_

#include <sgx_eid.h>
#include <sgx_error.h>
#include <thread>
#include "Log.h"
#include "CrustStatus.h"

#if defined(__cplusplus)
extern "C"
{
#endif

void storage_confirm_file(const char *hash);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_STORAGE_H_ */
