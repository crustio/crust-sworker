#ifndef _APP_SRD_TEST_H_
#define _APP_SRD_TEST_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <string>
#include <vector>
#include <unordered_set>
#include "Json.hpp"
#include "Config.h"
#include "FileUtils.h"
#include "FormatUtils.h"
#include "DataBase.h"
#include "Log.h"
#include "EnclaveData.h"


#if defined(__cplusplus)
extern "C"
{
#endif

bool srd_change_test(long change);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_SRD_TEST_H_*/
