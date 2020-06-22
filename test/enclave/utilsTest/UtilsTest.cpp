#include "UtilsTest.h"

bool test_char_to_int()
{
    std::string char_nums = "0123456789";
    std::string char_lowerletters = "abcdef";
    std::string char_upperletters = "ABCDEF";
    std::string char_others = "hijklmn`~!@#$%^&*()_-=+[{}]\\|:;\"'<,.>?/";

    for (auto c : char_nums)
    {
        if (char_to_int(c) != c - '0')
            return false;
    }

    for (auto c : char_lowerletters)
    {
        if (char_to_int(c) != c - 'a' + 10)
            return false;
    }

    for (auto c : char_upperletters)
    {
        if (char_to_int(c) != c - 'A' + 10)
            return false;
    }

    for (auto c : char_others)
    {
        if (char_to_int(c) != 0)
            return false;
    }

    return true;
}

bool test_hexstring()
{
    size_t tmp_len = 32;
    uint8_t *tmp_buffer = (uint8_t*)malloc(tmp_len);
    if (tmp_buffer == NULL)
    {
        return true;
    }
    memset(tmp_buffer, 0, tmp_len);
    
    char *hex_tmp_buffer = hexstring(tmp_buffer, tmp_len);
    for (size_t i = 0; i < tmp_len * 2; i++)
    {
        if (!(hex_tmp_buffer[i] >= '0' && hex_tmp_buffer[i] <= '9') &&
                !(hex_tmp_buffer[i] >= 'a' && hex_tmp_buffer[i] <= 'f'))
            return false;
    }

    return true;
}

bool test_hexstring_safe()
{
    size_t tmp_len = 32;
    uint8_t *tmp_buffer = (uint8_t*)malloc(tmp_len);
    if (tmp_buffer == NULL)
    {
        return true;
    }
    memset(tmp_buffer, 0, tmp_len);
    
    std::string hex_tmp_buffer = hexstring_safe(tmp_buffer, tmp_len);
    for (size_t i = 0; i < tmp_len; i++)
    {
        if (!(hex_tmp_buffer[i] >= '0' && hex_tmp_buffer[i] <= '9') &&
                !(hex_tmp_buffer[i] >= 'a' && hex_tmp_buffer[i] <= 'f'))
            return false;
    }

    return true;
}

bool test_hex_string_to_bytes()
{

std::string hex_str = "\
00010203040506070809\
a0a1a2a3a4a5a6a7a8a9\
b0b1b2b3b4b5b6b7b8b9\
c0c1c2c3c4c5c6c7c8c9\
d0d1d2d3d4d5d6d7d8d9\
e0e1e2e3e4e5e6e7e8e9\
f0f1f2f3f4f5f6f7f8f9";

    uint8_t bytes[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 
        0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 
    };

    uint8_t *hex_2_bytes = hex_string_to_bytes(hex_str.c_str(), hex_str.size());

    if (memcmp(hex_2_bytes, bytes, hex_str.size() / 2) != 0)
        return false;

    return true;
}

bool test_seal_data_mrenclave()
{
    size_t buffer_len = 32;
    uint8_t *tmp_buffer = (uint8_t*)malloc(buffer_len);
    if (tmp_buffer == NULL)
    {
        return true;
    }
    memset(tmp_buffer, 0, buffer_len);

    size_t sealed_data_size = 0;
    sgx_sealed_data_t *sealed_data = NULL;
    if (CRUST_SUCCESS != seal_data_mrenclave(tmp_buffer, buffer_len, &sealed_data, &sealed_data_size))
    {
        return false;
    }

    return true;
}

bool test_remove_char()
{
    std::string str_null = "";
    std::string str_same = "1111111111";
    std::string str_single = "1";
    std::string str_normal = "1212121212";

    remove_char(str_null, '1');
    if (str_null.compare("") != 0)
    {
        return false; 
    }

    remove_char(str_same, '1');
    if (str_same.compare("") != 0)
    {
        return false; 
    }

    remove_char(str_single, '1');
    if (str_single.compare("") != 0)
    {
        return false; 
    }

    remove_char(str_normal, '1');
    if (str_normal.compare("22222") != 0)
    {
        return false; 
    }

    return true;
}

void print_err(const char *info)
{
    std::string HRED = "\033[1;31m";
    std::string NC = "\033[0m";
    eprintf("%s%s%s", HRED.c_str(), info, NC.c_str());
}

void print_success(const char *info)
{
    std::string HGREEN = "\033[1;32m";
    std::string NC = "\033[0m";
    eprintf("%s%s%s", HGREEN.c_str(), info, NC.c_str());
}

bool test_utils()
{
    bool ret = true;
    if (!test_char_to_int())
    {
        print_err("x Test char_to_int failed!\n");
        ret = ret && false;
    }
    print_success("+ Test char_to_int successfully!\n");

    if (!test_hexstring())
    {
        print_err("x Test hexstring failed!\n");
        ret = ret && false;
    }
    print_success("+ Test hexstring successfully!\n");

    if (!test_hexstring_safe())
    {
        print_err("x Test hexstring_safe failed!\n");
        ret = ret && false;
    }
    print_success("+ Test hexstring_safe successfully!\n");

    if (!test_hex_string_to_bytes())
    {
        print_err("x Test hex_string_to_bytes failed!\n");
        ret = ret && false;
    }
    print_success("+ Test hex_string_to_bytes successfully!\n");

    if (!test_seal_data_mrenclave())
    {
        print_err("x Test seal_data_mrenclave failed!\n");
        ret = ret && false;
    }
    print_success("+ Test seal_data_mrenclave successfully!\n");

    if (!test_remove_char())
    {
        print_err("x Test remove_char failed!\n");
        ret = ret && false;
    }
    print_success("+ Test remove_char successfully!\n");

    return ret;
}
