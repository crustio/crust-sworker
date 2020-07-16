#ifndef _CRUST_STORAGE_H_
#define _CRUST_STORAGE_H_

#include <vector>
#include <set>
#include <tuple>
#include "sgx_trts.h"
#include "MerkleTree.h"
#include "Workload.h"
#include "Parameter.h"
#include "EUtils.h"

using namespace std;


#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t storage_seal_file(const char *p_tree, size_t tree_len, const char *path, size_t path_len, char *p_new_path);

crust_status_t storage_unseal_file(char **files, size_t files_num, const char *p_dir, char *p_new_path);

void storage_confirm_file(const char *hash);

crust_status_t storage_confirm_file_real();

void storage_delete_file(const char *hash);

crust_status_t storage_delete_file_real();

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_STORAGE_H_ */
