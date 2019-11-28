#ifndef _CRUST_MERKLE_TREE_H_
#define _CRUST_MERKLE_TREE_H_

#include <stddef.h>

typedef struct MerkleTreeStruct
{
    char* cid;
    size_t size;
    struct MerkleTreeStruct* children;
} MerkleTree;

#endif /* !_CRUST_MERKLE_TREE_H_ */
