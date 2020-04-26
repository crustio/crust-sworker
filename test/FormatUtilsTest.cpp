#define BOOST_TEST_MODULE format_utils_test
#include "FormatUtils.h"
#include <boost/test/included/unit_test.hpp>

bool offline_chain_mode = false;

BOOST_AUTO_TEST_SUITE(format_utils_test)

BOOST_AUTO_TEST_CASE(char_to_int_test)
{
    BOOST_CHECK(char_to_int(0) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
