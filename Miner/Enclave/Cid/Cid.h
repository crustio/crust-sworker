#ifndef _CRUST_CID_H_
#define _CRUST_CID_H_

#include "../Utils/Base58.h"
#include "../Utils/BigInteger.h"

bool is_cid_equal_hash(const char* cid, const unsigned char* hash);

#endif /* !_CRUST_CID_H_ */
