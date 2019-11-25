#include "FormatUtils.h"

int char_to_int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return 0;
}

void hex_string_to_bytes(const char *src, unsigned char *target)
{
    while (*src && src[1])
    {
        *(target++) = (unsigned char)(char_to_int(*src) * 16 + char_to_int(src[1]));
        src += 2;
    }
}
