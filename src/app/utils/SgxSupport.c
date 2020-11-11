#include "Resource.h"
#include "SgxSupport.h"
#include <sgx_urts.h>
#include <sgx_capable.h>
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

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef _WIN32
static HINSTANCE h_service = NULL;
#endif

#ifdef UAE_SERVICE_HAS_BOOL
typedef unsigned char bool;
#endif

#ifndef NULL
#define NULL 0
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef sgx_status_t(SGXAPI *fp_sgx_get_quote_size_t)(const uint8_t *p_sig_rl, uint32_t *p_quote_size);
typedef sgx_status_t(SGXAPI *fp_sgx_calc_quote_size_t)(const uint8_t *p_sig_rl, uint32_t p_sigrl_size, uint32_t *p_quote_size);

int sgx_support = SGX_SUPPORT_UNKNOWN;

static void *_load_libsgx_urts(void);
static void *_load_symbol(void *handle, const char *symbol, int *status);

static const char *dlerr = NULL;
static void *h_libsgx_uae_service = NULL;
static void *h_libsgx_urts = NULL;
static int l_libsgx_urts = 0;

/**
 * @description: Check if current host supports SGX
 * @return: support status
 */
int get_sgx_support(void)
{
#ifdef SGX_HW_SIM
	return SGX_SUPPORT_YES | SGX_SUPPORT_ENABLED;
#else
	sgx_device_status_t sgx_device_status;

	if (sgx_support != SGX_SUPPORT_UNKNOWN)
		return sgx_support;

	sgx_support = SGX_SUPPORT_NO;

	/* Check for the PSW */

	if (!have_sgx_psw())
		return sgx_support;

	sgx_support = SGX_SUPPORT_YES;

	/* Try to enable SGX */

	if (sgx_cap_get_status(&sgx_device_status) != SGX_SUCCESS)
		return sgx_support;

	/* If SGX isn't enabled yet, perform the software opt-in/enable. */

	if (sgx_device_status != SGX_ENABLED)
	{
		if (sgx_device_status == SGX_DISABLED_REBOOT_REQUIRED)
		{
			sgx_support |= SGX_SUPPORT_REBOOT_REQUIRED;
		}
		else if (sgx_device_status == SGX_DISABLED_REBOOT_REQUIRED)
		{
			sgx_support |= SGX_SUPPORT_ENABLE_REQUIRED;
		}
		/*switch (sgx_device_status) {
		    case SGX_DISABLED_REBOOT_REQUIRED:
		    	// A reboot is required
		    	sgx_support |= SGX_SUPPORT_REBOOT_REQUIRED;
		    	break;
		    case SGX_DISABLED_LEGACY_OS:
		    	// BIOS enabling is required
		    	sgx_support |= SGX_SUPPORT_ENABLE_REQUIRED;
		    	break;
            defalut:
		    	break;
		}*/

		return sgx_support;
	}

	sgx_support |= SGX_SUPPORT_ENABLED;

	return sgx_support;
#endif
}

/**
 * @description: Check if SGX PSW support
 * @return: Supported status
 */
int have_sgx_psw()
{
	return _load_libsgx_urts() == NULL ? 0 : 1;
}

/**
 * @description: Load SGX urts
 * @return: Pointer to SGX urts lib
 */
static void *_load_libsgx_urts()
{
	if (l_libsgx_urts == 0)
	{
#ifdef _WIN32
		h_libsgx_urts = LoadLibrary("libsgx_urts.dll");
#else
		h_libsgx_urts = dlopen("libsgx_urts.so", RTLD_GLOBAL | RTLD_NOW);
#endif
		l_libsgx_urts = (h_libsgx_urts == NULL) ? -1 : 1;
	}

	return h_libsgx_urts;
}

/**
 * @description: Load SGX urts
 * @return: Pointer to related function
 */
void *get_sgx_ufunction(const char *name)
{
	void *hsym = NULL;
	int status = 0;

	hsym = _load_symbol(h_libsgx_uae_service, name, &status);
	if (status == 1)
		return hsym;

	_load_symbol(h_libsgx_urts, name, &status);
	return (status == 1) ? hsym : NULL;
}

/**
 * @description: Load indicated symbol
 * @return: Pointer to related symbol
 */
static void *_load_symbol(void *handle, const char *symbol, int *status)
{
	void *hsym;

#ifdef _WIN32
	hsym = GetProcAddress((HMODULE)handle, symbol);
	*status = (dlerr == NULL) ? 1 : -1;
#else
	dlerr = dlerror();
	hsym = dlsym(handle, symbol);
	dlerr = dlerror();
	*status = (dlerr == NULL) ? 1 : -1;
#endif

	return hsym;
}

/**
 * @description: Caculate quote size
 * @return: Quote size
 */
int get_quote_size(sgx_status_t *status, uint32_t *qsz)
{
	fp_sgx_get_quote_size_t fp_sgx_get_quote_size = NULL;
	fp_sgx_calc_quote_size_t fp_sgx_calc_quote_size = NULL;

	// Does our PSW have the newer sgx_calc_quote_size?

#ifdef _WIN32
	if (h_service == NULL)
	{
		// We already did this in sgx_detect_win.cpp, so this should lib already
		// be open and loaded.
		h_service = LoadLibrary("sgx_uae_service.dll");
		if (h_service == NULL)
		{
			// We wouldn't get this far if the DLL isn't loaded, so something
			//horrible has happened if this is NULL.
			return 0;
		}
	}

	fp_sgx_calc_quote_size = (fp_sgx_calc_quote_size_t)GetProcAddress(h_service, "sgx_calc_quote_size");
	if (fp_sgx_calc_quote_size == NULL)
	{
		// Then fall back to sgx_get_quote_size
		fp_sgx_get_quote_size = (fp_sgx_get_quote_size_t)GetProcAddress(h_service, "sgx_get_quote_size");
		if (fp_sgx_get_quote_size == NULL)
			return 0;
		*status = fp_sgx_get_quote_size(NULL, qsz);
		return 1;
	}

	*status = fp_sgx_calc_quote_size(NULL, 0, qsz);

#else

	/* These stub functions abort if something goes horribly wrong */
	fp_sgx_calc_quote_size = (fp_sgx_calc_quote_size_t)get_sgx_ufunction("sgx_calc_quote_size");
	if (fp_sgx_calc_quote_size != NULL)
	{
		*status = (*fp_sgx_calc_quote_size)(NULL, 0, qsz);
		return 1;
	}

	fp_sgx_get_quote_size = (fp_sgx_get_quote_size_t)get_sgx_ufunction("sgx_get_quote_size");
	if (fp_sgx_get_quote_size == NULL)
		return 0;

	*status = (*fp_sgx_get_quote_size)(NULL, qsz);

#endif

	return 1;
}
