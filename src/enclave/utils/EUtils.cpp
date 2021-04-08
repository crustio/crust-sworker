#include "EUtils.h"
#include "Json.h"

using namespace std;

static char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
const char _hextable[] = "0123456789abcdef";

int eprint_base(char buf[], int flag);

/**
 * @description: Print flat normal info
 * @param fmt -> Output format
 * @return: the length of printed string
 */
int eprint_info(const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    return eprint_base(buf, 0);
}

/**
 * @description: Print flat debug info
 * @param fmt -> Output format
 * @return: the length of printed string
 */
int eprint_debug(const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    return eprint_base(buf, 1);
}

/**
 * @description: Flat printf base function
 * @param buf -> Print content
 * @param flag -> 0 for info, 1 for debug
 * @return: Print content length
 */
int eprint_base(char buf[], int flag)
{
    switch (flag)
    {
    case 0:
        ocall_print_info(buf);
        break;
    case 1:
        ocall_print_debug(buf);
        break;
    }
    return (int)strnlen(buf, LOG_BUF_SIZE - 1) + 1;
}

/**
 * @description: use ocall_log_info to print format string
 * @param fmt -> Output format
 * @return: the length of printed string
 */
int log_info(const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    ocall_log_info(buf);
    return (int)strnlen(buf, LOG_BUF_SIZE - 1) + 1;
}

/**
 * @description: use ocall_log_warn to print format string
 * @param fmt -> Output format
 * @return: the length of printed string
 */
int log_warn(const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    ocall_log_warn(buf);
    return (int)strnlen(buf, LOG_BUF_SIZE - 1) + 1;
}

/**
 * @description: use ocall_log_err to print format string
 * @param fmt -> Output format
 * @return: the length of printed string
 */
int log_err(const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    ocall_log_err(buf);
    return (int)strnlen(buf, LOG_BUF_SIZE - 1) + 1;
}

/**
 * @description: use ocall_log_debug to print format string
 * @param fmt -> Output format
 * @return: the length of printed string
 */
int log_debug(const char *fmt, ...)
{
    char buf[LOG_BUF_SIZE] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    ocall_log_debug(buf);
    return (int)strnlen(buf, LOG_BUF_SIZE - 1) + 1;
}

/**
 * @description: Change char to int
 * @param input -> Input character
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
 * @description: Transform string to hexstring
 * @param vsrc -> Source byte array
 * @param len -> Srouce byte array length
 * @return: Hexstringed data
 */
char *hexstring(const void *vsrc, size_t len)
{
    size_t i, bsz;
    const uint8_t *src = (const uint8_t *)vsrc;
    char *bp;

    bsz = len * 2 + 1; /* Make room for NULL byte */
    if (bsz >= _hex_buffer_size)
    {
        /* Allocate in 1K increments. Make room for the NULL byte. */
        size_t newsz = 1024 * (bsz / 1024) + ((bsz % 1024) ? 1024 : 0);
        _hex_buffer_size = newsz;
        _hex_buffer = (char *)enc_realloc(_hex_buffer, newsz);
        if (_hex_buffer == NULL)
        {
            return NULL;
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
 * @param vsrc -> Source byte array
 * @param len -> Srouce byte array length
 * @return: Hexstringed data
 */
std::string hexstring_safe(const void *vsrc, size_t len)
{
    size_t i;
    const uint8_t *src = (const uint8_t *)vsrc;
    char *hex_buffer = (char *)enc_malloc(len * 2);
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

    std::string ans(hex_buffer, len * 2);

    free(hex_buffer);

    return ans;
}

/**
 * @description: Byte vector to string
 * @param bytes -> Byte vector
 * @return: Hexstring of byte vector
 */
std::string byte_vec_to_string(std::vector<uint8_t> bytes)
{
    return hexstring_safe(bytes.data(), bytes.size());
}

/**
 * @description: Convert hexstring to bytes array, note that
 * the size of got data is half of len
 * @param src -> Source char*
 * @param len -> Source char* length
 * @return: Bytes array
 */
uint8_t *hex_string_to_bytes(const void *src, size_t len)
{
    if (len % 2 != 0 || len == 0)
    {
        return NULL;
    }

    const char *rsrc = (const char *)src;
    uint8_t *p_target;
    uint8_t *target = (uint8_t *)enc_malloc(len / 2);
    if (target == NULL)
    {
        return NULL;
    }
    memset(target, 0, len / 2);
    p_target = target;
    for (size_t i = 0; i < len; i += 2)
    {
        *(target++) = (uint8_t)(char_to_int(rsrc[0]) * 16 + char_to_int(rsrc[1]));
        rsrc += 2;
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
 * @description: Seal data by using input bytes with MRENCLAVE method
 * @param p_src -> bytes for seal
 * @param src_len -> the length of input bytes
 * @param p_sealed_data -> the output of seal
 * @param sealed_data_size -> the length of output bytes
 * @return: Seal status
 */
crust_status_t seal_data_mrenclave(const uint8_t *p_src, size_t src_len,
        sgx_sealed_data_t **p_sealed_data, size_t *sealed_data_size)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;

    uint32_t sealed_data_sz = sgx_calc_sealed_data_size(0, src_len);
    *p_sealed_data = (sgx_sealed_data_t *)enc_malloc(sealed_data_sz);
    if (*p_sealed_data == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(*p_sealed_data, 0, sealed_data_sz);
    sgx_attributes_t sgx_attr;
    sgx_attr.flags = 0xFF0000000000000B;
    sgx_attr.xfrm = 0;
    sgx_misc_select_t sgx_misc = 0xF0000000;
    sgx_status = Sgx_seal_data_ex(0x0001, sgx_attr, sgx_misc,
            0, NULL, src_len, p_src, sealed_data_sz, *p_sealed_data);

    if (SGX_SUCCESS != sgx_status)
    {
        log_err("Seal data failed!Error code:%lx\n", sgx_status);
        crust_status = CRUST_SEAL_DATA_FAILED;
        *p_sealed_data = NULL;
    }

    *sealed_data_size = (size_t)sealed_data_sz;

    return crust_status;
}

/**
 * @description: Seal data by using input bytes with MRSIGNER method
 * @param p_src -> bytes for seal
 * @param src_len -> the length of input bytes
 * @param p_sealed_data -> the output of seal
 * @param sealed_data_size -> the length of output bytes
 * @return: Seal status
 */
crust_status_t seal_data_mrsigner(const uint8_t *p_src, size_t src_len,
        sgx_sealed_data_t **p_sealed_data, size_t *sealed_data_size)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    uint8_t *p_src_r = const_cast<uint8_t *>(p_src);

    uint32_t sealed_data_sz = sgx_calc_sealed_data_size(0, src_len);
    *p_sealed_data = (sgx_sealed_data_t *)enc_malloc(sealed_data_sz);
    if (*p_sealed_data == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }

    memset(*p_sealed_data, 0, sealed_data_sz);

    int ret = sgx_is_within_enclave(p_src, src_len);
    if (ret == 0)
    {
        p_src_r = (uint8_t *)enc_malloc(src_len);
        if (p_src_r == NULL)
        {
            return CRUST_MALLOC_FAILED;
        }
        memset(p_src_r, 0, src_len);
        memcpy(p_src_r, p_src, src_len);
    }
    Defer def_src_r([&p_src_r, &ret](void) {
        if (ret == 0)
        {
            free(p_src_r);
        }
    });
    sgx_status = Sgx_seal_data(0, NULL, src_len, p_src_r, sealed_data_sz, *p_sealed_data);
    if (SGX_SUCCESS != sgx_status)
    {
        log_err("Seal data failed!Error code:%lx\n", sgx_status);
        free(*p_sealed_data);
        *p_sealed_data = NULL;
        return CRUST_SEAL_DATA_FAILED;
    }

    *sealed_data_size = (size_t)sealed_data_sz;

    return crust_status;
}

/**
 * @description: Validate merkle tree in json format
 * @param tree -> Merkle tree json format
 * @return: Validate status
 */
crust_status_t validate_merkletree_json(json::JSON tree)
{
    if (tree[MT_LINKS].size() == 0)
    {
        return CRUST_SUCCESS;
    }

    if (tree[MT_LINKS].size() < 0)
    {
        return CRUST_UNEXPECTED_ERROR;
    }

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sha256_hash_t parent_hash;
    uint8_t *parent_hash_org = NULL;
    uint8_t *parent_data_hash = NULL;

    // Validate sub tree and get all sub trees hash data
    size_t children_buffer_size = tree[MT_LINKS].size() * HASH_LENGTH;
    uint8_t *children_hashs = (uint8_t *)enc_malloc(children_buffer_size);
    if (children_hashs == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    memset(children_hashs, 0, children_buffer_size);
    for (int i = 0; i < tree[MT_LINKS].size(); i++)
    {
        if (tree[MT_LINKS][i].hasKey(MT_LINKS))
        {
            if (validate_merkletree_json(tree[MT_LINKS][i]) != CRUST_SUCCESS)
            {
                crust_status = CRUST_INVALID_MERKLETREE;
                goto cleanup;
            }
        }
        std::string hash;
        hash = tree[MT_LINKS][i][MT_DATA_HASH].ToString();
        uint8_t *tmp_hash = hex_string_to_bytes(hash.c_str(), hash.size());
        if (tmp_hash == NULL)
        {
            crust_status = CRUST_UNEXPECTED_ERROR;
            goto cleanup;
        }
        memcpy(children_hashs + i * HASH_LENGTH, tmp_hash, HASH_LENGTH);
        free(tmp_hash);
    }

    // Compute and compare hash value
    sgx_sha256_msg(children_hashs, children_buffer_size, &parent_hash);
    parent_hash_org = hex_string_to_bytes(tree[MT_HASH].ToString().c_str(), HASH_LENGTH * 2);
    if (parent_hash_org == NULL)
    {
        crust_status = CRUST_MALLOC_FAILED;
        goto cleanup;
    }
    if (memcmp(parent_hash_org, parent_hash, HASH_LENGTH) != 0)
    {
        crust_status = CRUST_NOT_EQUAL;
        goto cleanup;
    }

cleanup:
    if (parent_data_hash != NULL)
        free(parent_data_hash);

    if (children_hashs != NULL)
        free(children_hashs);

    if (parent_hash_org != NULL)
        free(parent_hash_org);

    return crust_status;
}

/**
 * @description: Wrapper for malloc function, add tryout
 * @param size -> malloc buffer size
 * @return: Pointer to malloc buffer
 */
void *enc_malloc(size_t size)
{
    int tryout = 0;
    void *p = NULL;

    while (tryout++ < ENCLAVE_MALLOC_TRYOUT && p == NULL)
    {
        p = (void *)malloc(size);
    }

    return p;
}

/**
 * @description: Wrapper for realloc function, add tryout
 * @param p -> Realloc pointer
 * @param size -> realloc buffer size
 * @return: Realloc buffer pointer
 */
void *enc_realloc(void *p, size_t size)
{
    int tryout = 0;
    if (p != NULL)
    {
        free(p);
        p = NULL;
    }

    while (tryout++ < ENCLAVE_MALLOC_TRYOUT && p == NULL)
    {
        p = (void *)enc_malloc(size);
    }

    return p;
}

/**
 * @description: Malloc new size and copy old buffer to it
 * @param p -> Pointer to old buffer
 * @param old_size -> Old buffer size
 * @param new_size -> New buffer size
 * @return: Pointer to new buffer with old buffer data
 */
void *enc_crealloc(void *p, size_t old_size, size_t new_size)
{
    void *old_p = NULL;
    if (old_size != 0 && p != NULL)
    {
        old_p = (void *)enc_malloc(old_size);
        if (old_p == NULL)
        {
            free(p);
            return NULL;
        }
        memset(old_p, 0, old_size);
        memcpy(old_p, p, old_size);
    }

    p = (void *)enc_realloc(p, new_size);

    if (p == NULL)
    {
        if (old_p != NULL)
        {
            free(old_p);
        }
        return NULL;
    }

    if (old_p != NULL)
    {
        memcpy(p, old_p, old_size);
        free(old_p);
    }

    return p;
}

/**
 * @description: A wrapper for sgx_seal_data
 * @param additional_MACtext_length -> Additional data length
 * @param p_additional_MACtext -> Pointer to additional data
 * @param text2encrypt_length -> Text to be encrypted length
 * @param p_text2encrypt -> Pointer to be encrypted data
 * @param sealed_data_size -> Sealed data size
 * @param p_sealed_data -> Pointer to sealed data
 * @return: Seal result status
 */
sgx_status_t Sgx_seal_data(const uint32_t additional_MACtext_length,
                           const uint8_t *p_additional_MACtext,
                           const uint32_t text2encrypt_length,
                           const uint8_t *p_text2encrypt,
                           const uint32_t sealed_data_size,
                           sgx_sealed_data_t *p_sealed_data)
{
    uint8_t *p_test = (uint8_t *)enc_malloc(sealed_data_size);
    if (p_test == NULL)
    {
        log_err("Malloc memory failed!\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    free(p_test);

    return sgx_seal_data(additional_MACtext_length,
                         p_additional_MACtext,
                         text2encrypt_length,
                         p_text2encrypt,
                         sealed_data_size,
                         p_sealed_data);
}

/**
 * @description: A wrapper function for sgx_seal_data_ex
 * @param key_policy -> Key policy
 * @param attribute_mask -> Attribute mask
 * @param misc_mask -> Misc mask
 * @param additional_MACtext_length -> Additional data length
 * @param p_additional_MACtext -> Pointer to additional data
 * @param text2encrypt_length -> Text to be encrypted length
 * @param p_text2encrypt -> Pointer to be encrypted data
 * @param sealed_data_size -> Sealed data size
 * @param p_sealed_data -> Pointer to sealed data
 * @return: Seal result status
 */
sgx_status_t Sgx_seal_data_ex(const uint16_t key_policy,
                              const sgx_attributes_t attribute_mask,
                              const sgx_misc_select_t misc_mask,
                              const uint32_t additional_MACtext_length,
                              const uint8_t *p_additional_MACtext,
                              const uint32_t text2encrypt_length,
                              const uint8_t *p_text2encrypt,
                              const uint32_t sealed_data_size,
                              sgx_sealed_data_t *p_sealed_data)
{
    uint8_t *p_test = (uint8_t *)enc_malloc(sealed_data_size);
    if (p_test == NULL)
    {
        log_err("Malloc memory failed!\n");
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    free(p_test);

    return sgx_seal_data_ex(key_policy,
                            attribute_mask,
                            misc_mask,
                            additional_MACtext_length,
                            p_additional_MACtext,
                            text2encrypt_length,
                            p_text2encrypt,
                            sealed_data_size,
                            p_sealed_data);
}

/**
 * @description: Remove indicated character from given string
 * @param data -> Reference to given string
 * @param c -> Indicated character
 */
void remove_char(std::string &data, char c)
{
    data.erase(std::remove(data.begin(), data.end(), c), data.end());
}

/**
 * @description: Replace org_str to det_str in data
 * @param data -> Reference to origin data
 * @param org_str -> Replaced string
 * @param det_str -> Replaced to string
 */
void replace(std::string &data, std::string org_str, std::string det_str)
{
    size_t spos, epos;
    spos = epos = 0;

    while (true)
    {
        spos = data.find(org_str, epos);
        if (spos == data.npos)
        {
            break;
        }
        data.replace(spos, org_str.size(), det_str);
        epos = spos + det_str.size();
    }
}

/**
 * @description: Store large data
 * @param data -> To be stored data
 * @param data_size -> To be stored data size
 * @param p_func -> Store function
 * @param mutex -> Mutex lock to sync data
 */
void store_large_data(const uint8_t *data, size_t data_size, p_ocall_store p_func, sgx_thread_mutex_t &mutex)
{
    sgx_thread_mutex_lock(&mutex);
    if (data_size > OCALL_STORE_THRESHOLD)
    {
        size_t offset = 0;
        size_t part_size = 0;
        bool cover = true;
        while (data_size > offset)
        {
            part_size = std::min(data_size - offset, (size_t)OCALL_STORE_THRESHOLD);
            p_func(reinterpret_cast<const char *>(data + offset), part_size, cover);
            offset += part_size;
            cover = false;
        }
    }
    else
    {
        p_func(reinterpret_cast<const char *>(data), data_size, true);
    }
    sgx_thread_mutex_unlock(&mutex);
}

/**
 * @description: base64 decode function
 * @param msg -> To be decoded message
 * @param sz -> Message size
 * @return: Decoded result
 */
char *base64_decode(const char *msg, size_t *sz)
{
    BIO *b64, *bmem;
    char *buf;
    size_t len = strlen(msg);

    buf = (char *)enc_malloc(len + 1);
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

    *sz = rsz;

    BIO_free_all(bmem);

    return buf;
}

/**
 * @description: base58 encode function
 * @param input -> To be encoded message
 * @param len -> Message size
 * @return: Encoded result
 */
std::string base58_encode(const uint8_t *input, size_t len)
{
    int length = 0, pbegin = 0, pend;
    if (!(pend = len))
    {
        return "";
    }

    int size = 1 + base58_ifactor * (double)(pend - pbegin);
    unsigned char b58[size] = {0};
    while (pbegin != pend)
    {
        unsigned int carry = input[pbegin];
        int i = 0;
        for (int it1 = size - 1; (carry || i < length) && (it1 != -1); it1--, i++)
        {
            carry += 256 * b58[it1];
            b58[it1] = carry % 58;
            carry /= 58;
        }
        if (carry)
        {
            return 0;
        }
        length = i;
        pbegin++;
    }
    int it2 = size - length;
    while ((it2 - size) && !b58[it2])
    {
        it2++;
    }

    std::string res(size - it2, '\0');
    size_t res_index = 0;
    for (; it2 < size; ++it2)
    {
        res[res_index] = BASE58_ALPHABET[b58[it2]];
        res_index++;
    }

    return res;
}

/**
 * @description: convert hash to cid function
 * @param hash -> To be encoded hash
 * @return: CID
 */
std::string hash_to_cid(const uint8_t *hash)
{
    int length = 0, pbegin = 0, pend = HASH_LENGTH + 2;
    int size = 1 + base58_ifactor * (double)(pend - pbegin);
    unsigned char b58[size] = {0};
    while (pbegin != pend)
    {
        unsigned int carry = pbegin == 0 ? 18 : pbegin == 1 ? 32 : hash[pbegin - 2];
        int i = 0;
        for (int it1 = size - 1; (carry || i < length) && (it1 != -1); it1--, i++)
        {
            carry += 256 * b58[it1];
            b58[it1] = carry % 58;
            carry /= 58;
        }
        if (carry)
        {
            return 0;
        }
        length = i;
        pbegin++;
    }
    int it2 = size - length;
    while ((it2 - size) && !b58[it2])
    {
        it2++;
    }

    std::string res(size - it2, '\0');
    size_t res_index = 0;
    for (; it2 < size; ++it2)
    {
        res[res_index] = BASE58_ALPHABET[b58[it2]];
        res_index++;
    }

    return res;
}

/**
 * @description: Unseal decrypted data
 * @param data -> Pointer to sealed data
 * @param p_decrypted_data -> Pointer to pointer decrypted data
 * @param decrypted_data_len -> Poniter to decrypted data length
 * @return: Unseal result
 */
crust_status_t unseal_data_mrsigner(const sgx_sealed_data_t *data,
                                    uint8_t **p_decrypted_data,
                                    uint32_t *decrypted_data_len)
{
    *decrypted_data_len = sgx_get_encrypt_txt_len(data);
    *p_decrypted_data = (uint8_t *)enc_malloc(*decrypted_data_len);
    if (*p_decrypted_data == NULL)
    {
        return CRUST_MALLOC_FAILED;
    }
    Defer defer_decrypted_data([&p_decrypted_data](void) { free(*p_decrypted_data); });
    memset(*p_decrypted_data, 0, *decrypted_data_len);

    // Do unseal
    sgx_status_t sgx_status = sgx_unseal_data(data, NULL, NULL, *p_decrypted_data, decrypted_data_len);
    if (SGX_SUCCESS != sgx_status)
    {
        log_err("SGX unseal failed! Internal error:%lx\n", sgx_status);
        return CRUST_UNSEAL_DATA_FAILED;
    }

    return CRUST_SUCCESS;
}
