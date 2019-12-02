#ifndef _CRUST_NODE_H_
#define _CRUST_NODE_H_

#include <stddef.h>

#define NODE_STRUCT_SPACE 55

typedef struct NodeStruct
{
    char* cid;
    size_t size;
} Node;

#endif /* !_CRUST_NODE_H_ */
