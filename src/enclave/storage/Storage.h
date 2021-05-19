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
#include "Persistence.h"
#include "Identity.h"

using namespace std;


#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t storage_seal_file(const char *cid);

crust_status_t storage_unseal_file(const char *data, size_t data_size);

crust_status_t storage_delete_file(const char *hash);

crust_status_t get_hashs_from_block(const uint8_t *block_data, size_t block_size, std::vector<uint8_t*> &hashs);

crust_status_t storage_ipfs_get_block(const char *cid, uint8_t **p_data, size_t *data_size);

crust_status_t storage_ipfs_cat(const char *cid, uint8_t **p_data, size_t *data_size);

crust_status_t storage_ipfs_add(uint8_t *p_data, size_t data_size, char **cid);

crust_status_t storage_get_file(const char *path, uint8_t **p_data, size_t *data_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_STORAGE_H_ */
