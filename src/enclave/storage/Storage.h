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

#define FILE_DELETE_TIMEOUT 50

using namespace std;


#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t storage_seal_file_start(const char *root, const char *root_b58);

crust_status_t storage_seal_file_end(const char *root);

crust_status_t storage_seal_file(const char *root, const uint8_t *data, size_t data_size, bool is_link, char *path, size_t path_size);

crust_status_t storage_unseal_file(const char *path, uint8_t *p_unsealed_data, size_t unseal_data_size, size_t *p_decrypted_data_size);

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
