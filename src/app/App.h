#ifndef _CRUST_APP_H_
#define _CRUST_APP_H_

#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <sgx_uae_launch.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_urts.h>

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>
#include <unistd.h>
#include "Config.h"
#include "Process.h"
#include "Log.h"
#include "Srd.h"
#include "Resource.h"

int main_daemon(void);

#endif /* !_CRUST_APP_H_ */
