#include "EUtils.h"
#include "EJson.h"

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
int eprint_info(const char* fmt, ...)
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
 * @description: Transform string to hexstring, thread safe
 * @param vsrc -> Source byte array
 * @param len -> Srouce byte array length
 * @return: Hexstringed data
 */
std::string hexstring_safe(const void *vsrc, size_t len)
{
    size_t i;
    const unsigned char *src = (const unsigned char *)vsrc;
    char *hex_buffer = (char*)enc_malloc(len * 2);
    if (hex_buffer == NULL)
    {
        return "";
    }
    memset(hex_buffer, 0, len * 2);
    char *bp;

    for (i = 0, bp = hex_buffer; i < len; ++i)
    {
        *bp = (uint8_t)_hextable[src[i] >> 4];
        ++bp;
        *bp = (uint8_t)_hextable[src[i] & 0xf];
        ++bp;
    }

    std::string ans(hex_buffer, len * 2);

    free(hex_buffer);

    return ans;
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
    if (len % 2 != 0)
    {
        return NULL;
    }

    const char *rsrc = (const char*)src;
    uint8_t *p_target;
    uint8_t *target = (uint8_t *)enc_malloc(len / 2);
    if (target == NULL)
    {
        return NULL;
    }
    memset(target, 0, len / 2);
    p_target = target;
    for (uint32_t i = 0; i < len; i+=2)
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

    uint32_t sealed_data_sz = sgx_calc_sealed_data_size(0, src_len);
    *p_sealed_data = (sgx_sealed_data_t *)enc_malloc(sealed_data_sz);
    if (p_sealed_data == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }

    memset(*p_sealed_data, 0, sealed_data_sz);

    sgx_status = Sgx_seal_data(0, NULL, src_len, p_src, sealed_data_sz, *p_sealed_data);
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
 * @description: Validate Merkle file tree
 * @param tree -> root of Merkle tree
 * @return: Validate status
 */
crust_status_t validate_merkle_tree_c(MerkleTree *tree)
{
    if (tree == NULL || tree->links_num == 0)
    {
        return CRUST_SUCCESS;
    }

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sha256_hash_t parent_hash;

    uint8_t *parent_hash_org = NULL;

    uint8_t *children_hashs = (uint8_t*)enc_malloc(tree->links_num * HASH_LENGTH);
    if (children_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(children_hashs, 0, tree->links_num * HASH_LENGTH);
    for (uint32_t i = 0; i < tree->links_num; i++)
    {
        if(validate_merkle_tree_c(tree->links[i]) != CRUST_SUCCESS)
        {
            crust_status = CRUST_INVALID_MERKLETREE;
            goto cleanup;
        }
        uint8_t *tmp_hash = hex_string_to_bytes(tree->links[i]->hash, HASH_LENGTH * 2);
        if (tmp_hash == NULL)
        {
            crust_status = CRUST_INVALID_MERKLETREE;
            goto cleanup;
        }
        memcpy(children_hashs + i * HASH_LENGTH, tmp_hash, HASH_LENGTH);
        free(tmp_hash);
    }

    // Compute and compare hash value
    sgx_sha256_msg(children_hashs, tree->links_num * HASH_LENGTH, &parent_hash);

    parent_hash_org = hex_string_to_bytes(tree->hash, HASH_LENGTH * 2);
    if (memcmp(parent_hash_org, parent_hash, HASH_LENGTH) != 0)
    {
        crust_status = CRUST_INVALID_MERKLETREE;
        goto cleanup;
    }


cleanup:

    free(children_hashs);

    if (parent_hash_org != NULL)
        free(parent_hash_org);

    return crust_status;
}

/**
 * @description: Validate merkle tree in json format
 * @param tree -> Merkle tree json format
 * @return: Validate status
 */
crust_status_t validate_merkletree_json(json::JSON tree)
{
    if (tree[MT_LINKS_NUM].ToInt() == 0)
    {
        return CRUST_SUCCESS;
    }

    if (tree[MT_LINKS_NUM].ToInt() != tree[MT_LINKS].size())
    {
        return CRUST_INVALID_MERKLETREE;
    }

    crust_status_t crust_status = CRUST_SUCCESS;
    sgx_sha256_hash_t parent_hash;

    uint8_t *parent_hash_org = NULL;

    uint8_t *children_hashs = (uint8_t*)enc_malloc(tree[MT_LINKS_NUM].ToInt() * HASH_LENGTH);
    if (children_hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return CRUST_MALLOC_FAILED;
    }
    memset(children_hashs, 0, tree[MT_LINKS_NUM].ToInt() * HASH_LENGTH);
    for (int i = 0; i < tree[MT_LINKS_NUM].ToInt(); i++)
    {
        if(validate_merkletree_json(tree[MT_LINKS][i]) != CRUST_SUCCESS)
        {
            crust_status = CRUST_INVALID_MERKLETREE;
            goto cleanup;
        }
        uint8_t *tmp_hash = hex_string_to_bytes(tree[MT_LINKS][i][MT_HASH].ToString().c_str(), HASH_LENGTH * 2);
        if (tmp_hash == NULL)
        {
            crust_status = CRUST_INVALID_MERKLETREE;
            goto cleanup;
        }
        memcpy(children_hashs + i * HASH_LENGTH, tmp_hash, HASH_LENGTH);
        free(tmp_hash);
    }

    // Compute and compare hash value
    sgx_sha256_msg(children_hashs, tree[MT_LINKS_NUM].ToInt() * HASH_LENGTH, &parent_hash);

    parent_hash_org = hex_string_to_bytes(tree[MT_HASH].ToString().c_str(), HASH_LENGTH * 2);
    if (memcmp(parent_hash_org, parent_hash, HASH_LENGTH) != 0)
    {
        crust_status = CRUST_INVALID_MERKLETREE;
        goto cleanup;
    }


cleanup:

    free(children_hashs);

    if (parent_hash_org != NULL)
        free(parent_hash_org);

    return crust_status;
}

/**
 * @description: Serialize MerkleTree to json string
 * @param root -> MerkleTree root node
 * @return: Json string
 */
string serialize_merkletree_to_json_string(MerkleTree *root)
{
    if (root == NULL)
    {
        return "";
    }

    uint32_t hash_len = strlen(root->hash);
    string node;
    std::string hex_hash_str = hexstring_safe(root->hash, hash_len);
    node.append("{\"" MT_SIZE "\":").append(to_string(root->size)).append(",")
        .append("\"" MT_LINKS_NUM "\":").append(to_string(root->links_num)).append(",")
        .append("\"" MT_HASH "\":\"").append(hex_hash_str).append("\",")
        .append("\"" MT_LINKS "\":[");

    for (size_t i = 0; i < root->links_num; i++)
    {
        node.append(serialize_merkletree_to_json_string(root->links[i])).append(",");
    }

    node.erase(node.size() - 1, 1);
    node.append("]}");

    return node;
}

/**
 * @description: Deserialize json string to MerkleTree
 * @param tree_json -> Tree in json format
 * @return: Deseialize tree in Merkle tree format
 */
MerkleTree *deserialize_json_to_merkletree(json::JSON tree_json)
{
    if (tree_json.JSONType() != json::JSON::Class::Object)
        return NULL;

    MerkleTree *root = new MerkleTree();
    std::string hash = tree_json[MT_HASH].ToString();
    size_t hash_len = hash.size() + 1;
    root->hash = (char*)enc_malloc(hash_len);
    if (root->hash == NULL)
    {
        log_err("Malloc memory failed!\n");
        return NULL;
    }
    memset(root->hash, 0, hash_len);
    memcpy(root->hash, hash.c_str(), hash.size());
    root->links_num = tree_json[MT_LINKS_NUM].ToInt();
    json::JSON children = tree_json[MT_LINKS];

    if (root->links_num != 0)
    {
        root->links = (MerkleTree**)malloc(root->links_num * sizeof(MerkleTree*));
        if (root->links == NULL)
        {
            log_err("Malloc memory failed!\n");
            return NULL;
        }
        for (uint32_t i = 0; i < root->links_num; i++)
        {
            MerkleTree *child = deserialize_json_to_merkletree(children[i]);
            if (child == NULL)
            {
                free(root->hash);
                free(root->links);
                return NULL;
            }
            root->links[i] = child;
        }
    }

    return root;
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
        p = (void*)malloc(size);
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

    while (tryout++ < ENCLAVE_MALLOC_TRYOUT && p == NULL)
    {
        p = (void*)realloc(p, size);
    }

    return p;
}

/**
 * @description: A wrapper for sgx_seal_data
 */
sgx_status_t Sgx_seal_data(const uint32_t additional_MACtext_length,
                           const uint8_t *p_additional_MACtext, const uint32_t text2encrypt_length,
                           const uint8_t *p_text2encrypt, const uint32_t sealed_data_size,
                           sgx_sealed_data_t *p_sealed_data)
{
    uint8_t *p_test = (uint8_t *)enc_malloc(sealed_data_size);
    if (p_test == NULL)
    {
        log_err("Malloc memory failed!\n");
        return SGX_ERROR_OUT_OF_MEMORY; 
    }
    free(p_test);

    return sgx_seal_data(additional_MACtext_length, p_additional_MACtext, 
            text2encrypt_length, p_text2encrypt, sealed_data_size, p_sealed_data);
}

/**
 * @description: A wrapper function for sgx_seal_data_ex
 */
sgx_status_t Sgx_seal_data_ex(const uint16_t key_policy,
                              const sgx_attributes_t attribute_mask,
                              const sgx_misc_select_t misc_mask,
                              const uint32_t additional_MACtext_length,
                              const uint8_t *p_additional_MACtext, const uint32_t text2encrypt_length,
                              const uint8_t *p_text2encrypt, const uint32_t sealed_data_size,
                              sgx_sealed_data_t *p_sealed_data)
{
    uint8_t *p_test = (uint8_t *)enc_malloc(sealed_data_size);
    if (p_test == NULL)
    {
        log_err("Malloc memory failed!\n");
        return SGX_ERROR_OUT_OF_MEMORY; 
    }
    free(p_test);

    return sgx_seal_data_ex(key_policy, attribute_mask, misc_mask,
            additional_MACtext_length, p_additional_MACtext, text2encrypt_length, 
            p_text2encrypt, sealed_data_size, p_sealed_data);
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
