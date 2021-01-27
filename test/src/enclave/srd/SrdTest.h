#ifndef _CRUST_SRD_TEST_H_
#define _CRUST_SRD_TEST_H_

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

void srd_change_test(long change, bool real);
size_t srd_decrease_test(size_t change);
void srd_increase_test();

#endif /* !_CRUST_SRD_TEST_H_ */
