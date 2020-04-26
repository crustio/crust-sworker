#define BOOST_TEST_MODULE format_utils_test
#include "Common.h"
#include <boost/test/included/unit_test.hpp>

bool offline_chain_mode = false;

BOOST_AUTO_TEST_SUITE(common_test)

BOOST_AUTO_TEST_CASE(remove_chars_from_string_test)
{
    std::string for_remove = "adb.hedf.h"
    remove_chars_from_string(for_remove, ".h");
    BOOST_CHECK(for_remove == "adbedf");
}

BOOST_AUTO_TEST_SUITE_END()