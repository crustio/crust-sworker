#ifndef _CRUST_APP_H_
#define _CRUST_APP_H_

#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <sgx_uae_service.h>
#include <sgx_urts.h>

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>
#include <unistd.h>
#include "Config.h"
#include "SingleProcess.h"

/* variable definition */
typedef struct ra_session_struct
{
	unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
} ra_session_t;

int main_daemon(void);
int main_status(void);
int main_report(void);

#endif /* !_CRUST_APP_H_ */
