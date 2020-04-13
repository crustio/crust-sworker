#ifndef _CRUST_ENTRY_NETWORK_H_
#define _CRUST_ENTRY_NETWORK_H_

#include <string>
#include <stdlib.h>
#include "Common.h"
#include "Log.h"
#include "HttpLib.h"
#include "SgxSupport.h"

#define OPT_ISSET(x, y) x &y
#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#define OPT_PSE 0x01
#define OPT_NONCE 0x02
#define OPT_LINK 0x04
#define OPT_PUBKEY 0x08

bool entry_network(Config *p_config, std::string &tee_identity_out);

#endif /* !_CRUST_ENTRY_NETWORK_H_ */
