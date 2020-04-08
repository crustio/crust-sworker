#ifndef _CRUST_STORAGE_H_
#define _CRUST_STORAGE_H_

#include <vector>
#include <set>
#include <tuple>
#include "sgx_trts.h"
#include "Node.h"
#include "MerkleTree.h"
#include "Workload.h"

#define LEAF_SEPARATOR  "+leaf+"

using namespace std;


#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t storage_validate_merkle_tree(MerkleTree *root);

crust_status_t storage_seal_file_data(const uint8_t *root_hash, uint32_t root_hash_len,
        const uint8_t *p_src, size_t src_len, uint8_t *p_sealed_data, size_t sealed_data_size);

crust_status_t storage_unseal_file_data(const uint8_t *p_sealed_data, size_t sealed_data_size,
        uint8_t *p_unsealed_data, uint32_t unsealed_data_size);

crust_status_t storage_gen_new_merkle_tree(const uint8_t *root_hash, uint32_t root_hash_len);

crust_status_t storage_validate_meaningful_data();

string storage_ser_merkle_tree(MerkleTree *tree);
crust_status_t storage_deser_merkle_tree(MerkleTree **root, string ser_tree, size_t &spos);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_STORAGE_H_ */
