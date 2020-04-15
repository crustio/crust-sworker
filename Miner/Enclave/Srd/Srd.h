#ifndef _CRUST_SRD_H_
#define _CRUST_SRD_H_

#include <vector>
#include <string>
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "Workload.h"
#include "EUtils.h"
#include "PathHelper.h"

void srd_increase_empty(const char *path);
size_t srd_decrease_empty(const char *path, size_t change);

#endif /* !_CRUST_SRD_H_ */
