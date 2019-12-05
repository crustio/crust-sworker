#include "Cid.h"

bool is_cid_equal_hash(const char *cid, const unsigned char *hash)
{
    BigInteger big_cid(0);
    BigInteger base_for_58(1);
    for (int i = (int)strlen(cid) - 1; i >= 0; i--)
    {
        big_cid = big_cid + ALPHABET_MAP[(int)cid[i]] * base_for_58;
        base_for_58 = base_for_58 * 58;
    }

    BigInteger big_block(0);
    BigInteger base_for_256(1);
    for (int i = 31; i >= 0; i--)
    {
        big_block = big_block + hash[i] * base_for_256;
        base_for_256 = base_for_256 * 256;
    }

    big_block = big_block + 32 * base_for_256;
    base_for_256 = base_for_256 * 256;
    big_block = big_block + 18 * base_for_256;

    return big_cid == big_block;
}
