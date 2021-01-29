#ifndef _SGX_SUPPORT_H_
#define _SGX_SUPPORT_H_

#pragma once

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sgx_edger8r.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_urts.h>
#include <sgx_urts.h>
#include <sgx_capable.h>

#include "Resource.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#define SGX_SUPPORT_UNKNOWN 0x00000000
#define SGX_SUPPORT_NO 0x08000000
#define SGX_SUPPORT_YES 0x00000001
#define SGX_SUPPORT_ENABLED 0x00000002
#define SGX_SUPPORT_REBOOT_REQUIRED 0x00000004
#define SGX_SUPPORT_ENABLE_REQUIRED 0x00000008

#ifdef __cplusplus
extern "C"
{
#endif

    int get_sgx_support(void);
    int get_quote_size(sgx_status_t *status, uint32_t *quote_size);
    int have_sgx_psw(void);
    void *get_sgx_ufunction(const char *name); /* Returns func pointer */

#ifdef __cplusplus
}
#endif

#endif /* !_SGX_SUPPORT_H_ */
