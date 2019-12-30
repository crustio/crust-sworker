#ifndef _CRUST_NODE_H_
#define _CRUST_NODE_H_

#include <stddef.h>

typedef struct NodeStruct
{
    unsigned char *hash;
    size_t size;
    char exist;
} Node;

#endif /* !_CRUST_NODE_H_ */
