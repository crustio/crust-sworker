#ifndef _CRUST_NODE_H_
#define _CRUST_NODE_H_

#include <stddef.h>

typedef struct NodeStruct
{
    size_t size;
    char exist;
    unsigned char *hash;
} Node;

#endif /* !_CRUST_NODE_H_ */
