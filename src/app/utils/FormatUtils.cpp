#include "FormatUtils.h"

static char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
const char _hextable[] = "0123456789abcdef";

/**
 * @description: Change char to int
 * @param input -> Input char
 * @return: Corresponding int
 */
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

/**
 * @description: Convert hexstring to bytes array
 * @param src -> Source char*
 * @param len -> Source char* length
 * @return: Bytes array
 */
uint8_t *hex_string_to_bytes(const char *src, size_t len)
{
    if(len % 2 != 0 || 0 == len)
    {
        return NULL;
    }

    uint8_t *p_target;
    uint8_t *target = (uint8_t*)malloc(len/2);
    memset(target, 0, len/2);
    p_target = target;
    while (*src && src[1])
    {
        *(target++) = (uint8_t)(char_to_int(*src) * 16 + char_to_int(src[1]));
        src += 2;
    }

    return p_target;
}

/**
 * @description: Print hexstring
 * @param vsrc -> Pointer to source data
 * @param len -> Source data length
 */
void print_hexstring(const void *vsrc, size_t len)
{
    const unsigned char *sp = (const unsigned char *)vsrc;
    size_t i;
    for (i = 0; i < len; ++i)
    {
        printf("%02x", sp[i]);
    }
}

/**
 * @description: Dehexstring data
 * @param dest -> Pointer to destination data
 * @param vsrc -> Pointer to source data
 * @param len -> Source data length
 * @return: status
 */
int from_hexstring(unsigned char *dest, const void *vsrc, size_t len)
{
    size_t i;
    const unsigned char *src = (const unsigned char *)vsrc;

    for (i = 0; i < len; ++i)
    {
        unsigned int v;
#ifdef _WIN32
        if (sscanf_s(&src[i * 2], "%2xhh", &v) == 0)
            return 0;
#else
        if (sscanf(reinterpret_cast<const char*>(&src[i * 2]), "%2xhh", &v) == 0)
            return 0;
#endif
        dest[i] = (unsigned char)v;
    }

    return 1;
}

/**
 * @description: Transform string to hexstring
 * @param vsrc -> Pointer to original data buffer
 * @param len -> Original data buffer length
 * @return: Hexstringed data
 */
char *hexstring(const void *vsrc, size_t len)
{
    size_t i, bsz;
    const unsigned char *src = (const unsigned char *)vsrc;
    char *bp;

    bsz = len * 2 + 1; /* Make room for NULL byte */
    if (bsz >= _hex_buffer_size)
    {
        /* Allocate in 1K increments. Make room for the NULL byte. */
        size_t newsz = 1024 * (bsz / 1024) + ((bsz % 1024) ? 1024 : 0);
        _hex_buffer_size = newsz;
        _hex_buffer = (char *)realloc(_hex_buffer, newsz);
        if (_hex_buffer == NULL)
        {
            return const_cast<char*>("(out of memory)");
        }
    }

    for (i = 0, bp = _hex_buffer; i < len; ++i)
    {
        *bp = _hextable[src[i] >> 4];
        ++bp;
        *bp = _hextable[src[i] & 0xf];
        ++bp;
    }
    _hex_buffer[len * 2] = 0;

    return _hex_buffer;
}

/**
 * @description: Transform string to hexstring, thread safe
 * @param vsrc -> Pointer to original data buffer
 * @param len -> Original data buffer length
 * @return: Hexstringed data
 */
std::string hexstring_safe(const void *vsrc, size_t len)
{
    size_t i;
    const unsigned char *src = (const unsigned char *)vsrc;
    char *hex_buffer = (char*)malloc(len * 2);
    if (hex_buffer == NULL)
    {
        return "";
    }
    memset(hex_buffer, 0, len * 2);
    char *bp;

    for (i = 0, bp = hex_buffer; i < len; ++i)
    {
        *bp = _hextable[src[i] >> 4];
        ++bp;
        *bp = _hextable[src[i] & 0xf];
        ++bp;
    }

    std::string ret = std::string(hex_buffer, len * 2);
    free(hex_buffer);

    return ret;
}

/**
 * @description: Base64 encode data
 * @param msg -> Pointer to messgae data
 * @param sz -> Message data size
 * @return: Base64 encoded data
 */
char *base64_encode(const char *msg, size_t sz)
{
    BIO *b64, *bmem;
    char *bstr, *dup;
    size_t len;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());

    /* Single line output, please */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_push(b64, bmem);

    if (BIO_write(b64, msg, (int)sz) == -1)
    {
        BIO_free(bmem);
        BIO_free(b64);
        return NULL;
    }

    if (BIO_flush(b64)) {}

    len = (size_t)BIO_get_mem_data(bmem, &bstr);
    dup = (char *)malloc(len + 1);
    if (dup == NULL)
    {
        BIO_free(bmem);
        BIO_free(b64);
        return NULL;
    }

    memcpy(dup, bstr, len);
    dup[len] = 0;

    BIO_free(bmem);
    BIO_free(b64);

    return dup;
}

/**
 * @description: Base64 decode data
 * @param msg -> Pointer to messgae data
 * @param sz -> Message data size
 * @return: Decoded data
 */
char *base64_decode(const char *msg, size_t *sz)
{
    BIO *b64, *bmem;
    char *buf;
    size_t len = strlen(msg);

    buf = (char *)malloc(len + 1);
    if (buf == NULL)
        return NULL;
    memset(buf, 0, len + 1);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf(msg, (int)len);

    BIO_push(b64, bmem);

    int rsz = BIO_read(b64, buf, (int)len);
    if (rsz == -1)
    {
        free(buf);
        return NULL;
    }

    *sz = (size_t)rsz;

    BIO_free_all(bmem);

    return buf;
}

/**
 * @description: Numeral to hexstring
 * @param num -> Numeral
 * @return: Hex string
 */
std::string num_to_hexstring(size_t num)
{
    std::string ans;
    char buf[32];
    memset(buf, 0, 32);
    sprintf(buf, "%lx", num);

    ans.append(buf);

    return ans;
}
