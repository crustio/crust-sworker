#include "EncalveTestEntrance.h"

void print_err(const char *info)
{
    std::string HRED = "\033[1;31m";
    std::string NC = "\033[0m";
    eprint_info("%s%s%s", HRED.c_str(), info, NC.c_str());
}

void print_success(const char *info)
{
    std::string HGREEN = "\033[1;32m";
    std::string NC = "\033[0m";
    eprint_info("%s%s%s", HGREEN.c_str(), info, NC.c_str());
}

bool test_all_utils()
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

bool test_all_storage()
{
    bool ret = true;
    if (!test_get_hashs_from_block())
    {
        print_err("x Test get_hashs_from_block failed!\n");
        ret = ret && false;
    }
    print_success("+ Test get_hashs_from_block successfully!\n");

    return ret;
}

bool test_enclave_unit()
{
    bool ret = true;
    print_success("------------ Test utils ------------\n\n");
    if (!test_all_utils())
    {
        ret = ret && false;
    }

    print_success("\n------------ Test storage ------------\n\n");
    if (!test_all_storage())
    {
        ret = ret && false;
    }
    
    return ret;
}
