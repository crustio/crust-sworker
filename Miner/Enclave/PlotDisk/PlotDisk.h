#ifndef _CRUST_PLOT_DISK_H_
#define _CRUST_PLOT_DISK_H_

#include "../Enclave.h"
#include "../Utils/FormatHelper.h"
#include <vector>
#include <string>
#include "sgx_trts.h"
#include "sgx_thread.h"

#define PLOT_RAND_DATA_LENGTH 1000
#define PLOT_RAND_DATA_NUM 1
#define PLOT_HASH_LENGTH 32

sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;
std::vector<unsigned char *> all_g_hashs;

std::string get_file_path(const char *path, const size_t now_index);
void save_file(const char *dir_path, size_t index, sgx_sha256_hash_t hash, const unsigned char *data, size_t data_size);

#endif /* !_CRUST_PLOT_DISK_H_ */
