#ifndef _CRUST_PLOT_DISK_H_
#define _CRUST_PLOT_DISK_H_

#include "../Utils/FormatHelper.h"
#include "../Utils/PathHelper.h"
#include "../Models/Workload.h"
#include <vector>
#include <string>
#include "sgx_trts.h"
#include "sgx_thread.h"

#define PLOT_RAND_DATA_LENGTH 1048576
#define PLOT_RAND_DATA_NUM 1024
#define PLOT_HASH_LENGTH 32

Workload *get_workload();

#endif /* !_CRUST_PLOT_DISK_H_ */
