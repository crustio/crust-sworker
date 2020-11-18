#ifndef _CRUST_IPFS_OCALLS_H_
#define _CRUST_IPFS_OCALLS_H_

#include "CrustStatus.h"
#include "Ipfs.h"
#include "Log.h"

#if defined(__cplusplus)
extern "C"
{
#endif

bool ocall_ipfs_online();
crust_status_t ocall_ipfs_block_get(const char *cid, unsigned char **p_data, size_t *len);
crust_status_t ocall_ipfs_cat(const char *cid, unsigned char **p_data, size_t *len);
crust_status_t ocall_ipfs_add(unsigned char *p_data, size_t len, char **cid, size_t *cid_len);

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_IPFS_OCALLS_H_ */
