#ifndef _CRUST_SRD_H_
#define _CRUST_SRD_H_

#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#include "sgx_trts.h"
#include "sgx_thread.h"

#include "Workload.h"
#include "EUtils.h"
#include "PathHelper.h"
#include "SafeLock.h"
#include "Parameter.h"

void srd_change();
crust_status_t srd_increase(const char *uuid);
size_t srd_decrease(size_t change);
void srd_remove_space(const char *data, size_t data_size);
long get_srd_task();
crust_status_t change_srd_task(long change, long *real_change);
crust_status_t srd_get_file(const char *path, uint8_t **p_data, size_t *data_size);

#endif /* !_CRUST_SRD_H_ */
