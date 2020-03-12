#include "EUtils.h"

static char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
const char _hextable[] = "0123456789abcdef";

/**
 * @description: use ocall_print_string to print format string
 * @return: the length of printed string
 */
int eprintf(const char *fmt, ...)
{
    char buf[BUFSIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZE - 1) + 1;
}

/**
 * @description: use ocall_eprint_string to print format string
 * @return: the length of printed string
 */
int cfeprintf(const char *fmt, ...)
{
    char buf[BUFSIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);
    ocall_eprint_string(buf);
    return (int)strnlen(buf, BUFSIZE - 1) + 1;
}

/**
 * @description: Change char to int
 * @return: Corresponding int
 * */
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
 * @description: Transform string to hexstring
 * @param vsrc -> Source byte array
 * @param len -> Srouce byte array length
 * @return: Hexstringed data
 * */
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
            return NULL;
        }
    }

    for (i = 0, bp = _hex_buffer; i < len; ++i)
    {
        *bp = (uint8_t)_hextable[src[i] >> 4];
        ++bp;
        *bp = (uint8_t)_hextable[src[i] & 0xf];
        ++bp;
    }
    _hex_buffer[len * 2] = 0;

    return _hex_buffer;
}

/**
 * @description: Convert hexstring to bytes array, note that
 * the size of got data is half of len
 * @param src -> Source char*
 * @param len -> Source char* length
 * @return: Bytes array
 * */
uint8_t *hex_string_to_bytes(const char *src, size_t len)
{
    if (len % 2 != 0)
    {
        return NULL;
    }

    uint8_t *p_target;
    uint8_t *target = (uint8_t *)malloc(len / 2);
    if (target == NULL)
    {
        return NULL;
    }
    memset(target, 0, len / 2);
    p_target = target;
    while (*src && src[1])
    {
        *(target++) = (uint8_t)(char_to_int(*src) * 16 + char_to_int(src[1]));
        src += 2;
    }

    return p_target;
}

/**
 * @description: convert byte array to hex string
 * @param in -> byte array
 * @param size -> the size of byte array
 * @return: hex string
 */
std::string unsigned_char_array_to_hex_string(const unsigned char *in, size_t size)
{
    char *result = new char[size * 2 + 1];
    size_t now_pos = 0;

    for (size_t i = 0; i < size; i++)
    {
        char *temp = unsigned_char_to_hex(in[i]);
        result[now_pos++] = temp[0];
        result[now_pos++] = temp[1];
        delete[] temp;
    }

    result[now_pos] = '\0';

    std::string out_str(result);
    delete[] result;
    return out_str;
}

/**
 * @description: convert byte array to byte vector
 * @param in -> byte array
 * @param size -> the size of byte array
 * @return: byte vector
 */
std::vector<unsigned char> unsigned_char_array_to_unsigned_char_vector(const unsigned char *in, size_t size)
{
    std::vector<unsigned char> out(size);
    std::copy(in, in + size, out.begin());
    return out;
}

/**
 * @description: convert byte to hex char array
 * @param in -> byte
 * @return: hex char array
 */
char *unsigned_char_to_hex(const unsigned char in)
{
    char *result = new char[2];

    if (in / 16 < 10)
    {
        result[0] = (char)(in / 16 + '0');
    }
    else
    {
        result[0] = (char)(in / 16 - 10 + 'a');
    }

    if (in % 16 < 10)
    {
        result[1] = (char)(in % 16 + '0');
    }
    else
    {
        result[1] = (char)(in % 16 - 10 + 'a');
    }

    return result;
}

/**
 * @description: seal data by using input bytes
 * @param p_src -> bytes for seal
 * @param src_len -> the length of input bytes
 * @param p_sealed_data -> the output of seal
 * @param sealed_data_size -> the length of output bytes
 * @return: status
 */
common_status_t seal_data_mrenclave(const uint8_t *p_src, size_t src_len,
                                    sgx_sealed_data_t **p_sealed_data, size_t *sealed_data_size)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    common_status_t common_status = CRUST_SUCCESS;

    uint32_t sealed_data_sz = sgx_calc_sealed_data_size(0, src_len);
    *p_sealed_data = (sgx_sealed_data_t *)malloc(sealed_data_sz);
    memset(*p_sealed_data, 0, sealed_data_sz);
    sgx_attributes_t sgx_attr;
    sgx_attr.flags = 0xFF0000000000000B;
    sgx_attr.xfrm = 0;
    sgx_misc_select_t sgx_misc = 0xF0000000;
    sgx_status = sgx_seal_data_ex(0x0001, sgx_attr, sgx_misc,
                                  0, NULL, src_len, p_src, sealed_data_sz, *p_sealed_data);

    if (SGX_SUCCESS != sgx_status)
    {
        cfeprintf("Seal data failed!Error code:%lx\n", sgx_status);
        common_status = CRUST_SEAL_DATA_FAILED;
        *p_sealed_data = NULL;
    }

    *sealed_data_size = (size_t)sealed_data_sz;

    return common_status;
}