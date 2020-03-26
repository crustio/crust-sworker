#ifndef _CRUST_VALIDATOR_H_
#define _CRUST_VALIDATOR_H_

#include <vector>
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "Node.h"
#include "MerkleTree.h"
#include "Workload.h"
#include "PathHelper.h"

/* Empty disk file verification ratio */
#define EMPTY_VALIDATE_RATE 1
/* Meaningful disk file verification ratio */
#define MEANINGFUL_FILE_VALIDATE_RATE 0.10
/* The blocks of meaningful disk file verification ratio */
#define MEANINGFUL_BLOCK_VALIDATE_RATE 0.05

void validate_empty_disk(const char *path);
bool validate_merkle_tree(MerkleTree *root, size_t *size);
void validate_meaningful_disk(const Node *files, size_t files_num);
std::vector<std::string> get_hashs_from_block(unsigned char *block_data, size_t block_size);

#endif /* !_CRUST_VALIDATOR_H_ */
