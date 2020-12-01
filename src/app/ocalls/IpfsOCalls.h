#ifndef _CRUST_IPFS_OCALLS_H_
#define _CRUST_IPFS_OCALLS_H_

#include "CrustStatus.h"
#include "DataBase.h"
#include "Ipfs.h"
#include "Log.h"
#include "EnclaveData.h"

#if defined(__cplusplus)
extern "C"
{
#endif

bool ocall_ipfs_online();
crust_status_t ocall_ipfs_get_block(const char *cid, uint8_t **p_data, size_t *data_size);
crust_status_t ocall_ipfs_cat(const char *cid, uint8_t **p_data, size_t *data_size);
crust_status_t ocall_ipfs_add(uint8_t *p_data, size_t len, char *cid, size_t cid_len);
crust_status_t ocall_ipfs_del(const char *cid);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_IPFS_OCALLS_H_ */
