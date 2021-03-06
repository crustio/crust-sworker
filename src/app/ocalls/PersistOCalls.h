#ifndef _CRUST_PERSIST_OCALLS_H_
#define _CRUST_PERSIST_OCALLS_H_

#include "CrustStatus.h"
#include "Config.h"
#include "Common.h"
#include "Log.h"
#include "DataBase.h"

#if defined(__cplusplus)
extern "C"
{
#endif

crust_status_t ocall_persist_add(const char *key, const uint8_t *value, size_t value_len);
crust_status_t ocall_persist_del(const char *key);
crust_status_t ocall_persist_set(const char *key, const uint8_t *value, size_t value_len, 
        size_t total_size, uint8_t **total_buf, size_t offset);
crust_status_t ocall_persist_get(const char *key, uint8_t **value, size_t *value_len);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_PERSIST_OCALLS_H_ */
