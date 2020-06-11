#ifndef _CRUST_VALIDATOR_H_
#define _CRUST_VALIDATOR_H_

#include <vector>
#include <unordered_set>
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "Node.h"
#include "MerkleTree.h"
#include "Workload.h"
#include "PathHelper.h"
#include "Persistence.h"
#include "EUtils.h"
#include "Parameter.h"

/* Meaningful disk file verification ratio */
#define MEANINGFUL_FILE_VALIDATE_RATE 0.10
#define MIN_VALIDATE_FILE_NUM 10
#define MAX_VALIDATE_BLOCK_NUM 16
/* The blocks of meaningful disk file verification ratio */
#define MEANINGFUL_BLOCK_VALIDATE_RATE 0.05
#define MAX_BLOCK_SIZE 1048576 /* 1024*1024 */

void validate_empty_disk();
void validate_meaningful_file();
std::vector<std::string> get_hashs_from_block(unsigned char *block_data, size_t block_size);

#endif /* !_CRUST_VALIDATOR_H_ */
