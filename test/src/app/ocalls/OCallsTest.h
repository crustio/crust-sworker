#ifndef _CRUST_OCALLS_TEST_H_
#define _CRUST_OCALLS_TEST_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <exception>

#include "CrustStatus.h"
#include "FileUtils.h"
#include "FormatUtils.h"
#include "Config.h"
#include "Common.h"
#include "Log.h"
#include "EnclaveData.h"
#include "WebsocketClient.h"
#include "Srd.h"
#include "SrdTest.h"
#include "DataBase.h"
#include "Chain.h"
#include "EntryNetwork.h"
#include "Chain.h"
#include "EnclaveDataTest.h"
#include "ValidateTest.h"

#if defined(__cplusplus)
extern "C"
{
#endif

void ocall_store_file_info_test(const char *info);
crust_status_t ocall_get_file_bench(const char *file_path, unsigned char **p_file, size_t *len);
crust_status_t ocall_get_file_block(const char *file_path, unsigned char **p_file, size_t *len);
crust_status_t ocall_srd_change_test(long change);
void ocall_recall_validate_file_bench();
void ocall_recall_validate_srd_bench();

#if defined(__cplusplus)
}
#endif

#endif /* !_CRUST_OCALLS_TEST_H_ */
