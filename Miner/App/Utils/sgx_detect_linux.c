/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


#include "config.h"
#include <sgx_urts.h>
#include <sgx_capable.h>
#include "sgx_stub.h"
#include "sgx_detect.h"
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef NULL
#define NULL 0
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

int sgx_support = SGX_SUPPORT_UNKNOWN;

int get_sgx_support()
{
#ifdef SGX_HW_SIM
	return SGX_SUPPORT_YES|SGX_SUPPORT_ENABLED;
#else
	sgx_device_status_t sgx_device_status;

	if (sgx_support != SGX_SUPPORT_UNKNOWN) return sgx_support;

	sgx_support = SGX_SUPPORT_NO;

	/* Check for the PSW */

	if (! have_sgx_psw()) return sgx_support;

	sgx_support = SGX_SUPPORT_YES;

	/* Try to enable SGX */

	if (sgx_cap_get_status(&sgx_device_status) != SGX_SUCCESS)
		return sgx_support;

	/* If SGX isn't enabled yet, perform the software opt-in/enable. */

	if (sgx_device_status != SGX_ENABLED) {
		switch (sgx_device_status) {
		case SGX_DISABLED_REBOOT_REQUIRED:
			/* A reboot is required. */
			sgx_support |= SGX_SUPPORT_REBOOT_REQUIRED;
			break;
		case SGX_DISABLED_LEGACY_OS:
			/* BIOS enabling is required */
			sgx_support |= SGX_SUPPORT_ENABLE_REQUIRED;
			break;
		}

		return sgx_support;
	}

	sgx_support |= SGX_SUPPORT_ENABLED;

	return sgx_support;
#endif
}

/* 
 * Used to search and create enclave on Linux 
 * */
sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) {
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
    }

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 ) {
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
    }

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) ) {
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
    }
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) ) {
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
    }

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) ) {
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
    }

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}
