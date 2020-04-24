#ifndef _CRUST_PERSISTENCE_H_
#define _CRUST_PERSISTENCE_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "CrustStatus.h"

#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t persist_add(const char *key, const uint8_t *value, size_t value_len);
crust_status_t persist_del(const char *key);
crust_status_t persist_set(const char *key, const uint8_t *value, size_t value_len);
crust_status_t persist_get(const char *key, uint8_t **value, size_t *value_len);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_PERSISTENCE_H_ */
