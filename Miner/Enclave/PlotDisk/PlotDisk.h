#ifndef _CRUST_PLOT_DISK_H_
#define _CRUST_PLOT_DISK_H_

#include <vector>
#include <string>
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "Workload.h"
#include "EUtils.h"
#include "FormatHelper.h"
#include "PathHelper.h"

void save_file(const char *g_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size);
void save_m_hashs_file(const char *g_path, const unsigned char *data, size_t data_size);

#endif /* !_CRUST_PLOT_DISK_H_ */
