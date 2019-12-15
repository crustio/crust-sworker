#include "FormatHelper.h"

std::string unsigned_char_array_to_hex_string(const unsigned char *in, size_t size)
{
    char *hex_char_array = unsigned_char_array_to_hex_char_array(in, size);
    std::string result(hex_char_array);
    delete[] hex_char_array;
    return result;
}

std::vector<unsigned char> unsigned_char_array_to_unsigned_char_vector(const unsigned char *in, size_t size)
{
    std::vector<unsigned char> out(size);
    std::copy(in, in + size, out.begin());
    return out;
}

char *unsigned_char_array_to_hex_char_array(const unsigned char *in, size_t size)
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
    return result;
}

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
