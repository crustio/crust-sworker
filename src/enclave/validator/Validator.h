#ifndef _CRUST_VALIDATOR_H_
#define _CRUST_VALIDATOR_H_

#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "Node.h"
#include "MerkleTree.h"
#include "Workload.h"
#include "PathHelper.h"
#include "Persistence.h"
#include "EUtils.h"
#include "Parameter.h"

#define SRD_VALIDATE_RATE 0.02
#define SRD_VALIDATE_MIN_NUM 64
/* Meaningful disk file verification ratio */
#define MEANINGFUL_VALIDATE_RATE 0.02
#define MEANINGFUL_VALIDATE_MIN_NUM 64
#define MEANINGFUL_VALIDATE_MIN_BLOCK_NUM 1
#define MAX_BLOCK_SIZE 1048576 /* 1024*1024 */

void validate_srd();
void validate_meaningful_file();

#endif /* !_CRUST_VALIDATOR_H_ */
