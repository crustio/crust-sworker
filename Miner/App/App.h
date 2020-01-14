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
//#include "sgx_error.h"
//#include "sgx_eid.h"
//#include "sgx_urts.h"
//#include "sgx_capable.h"
//#include "SgxSupport.h"
//#include "Enclave_u.h"

#include "Config.h"
//#include "ApiHandler.h"

//#include "Ipfs.h"
//#include "OCalls.h"
//#include "ValidationStatus.h"
//#include "FormatUtils.h"
//#include "Common.h"
//#include "Logfile.h"
//#include "config.h"
#include "Process.h"
//#include "Client.h"

//#define ENCLAVE_NAME "Enclave.signed.so"
//#define OPT_ISSET(x, y) x &y
//#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
//
//#define TOKEN_FILENAME "enclave.token"
//
//#define OPT_PSE 0x01
//#define OPT_NONCE 0x02
//#define OPT_LINK 0x04
//#define OPT_PUBKEY 0x08
//
//#ifdef __x86_64__
//#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
//#else
//#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
//#endif
//
//#define SESSION_STARTER  1
//#define SESSION_RECEIVER 2

using namespace std;

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
int main_report(const char *block_hash);

#endif /* !_CRUST_APP_H_ */
