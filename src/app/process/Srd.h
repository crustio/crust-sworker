#ifndef _APP_SRD_H_
#define _APP_SRD_H_

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


#if defined(__cplusplus)
extern "C"
{
#endif

json::JSON get_increase_srd_info(size_t &true_srd_capacity);
json::JSON get_decrease_srd_info(size_t &true_srd_capacity);
void srd_change(long change);
void srd_check_reserved(void);
void set_reserved_space(size_t reserved);
size_t get_reserved_space();
long get_old_reserved_space(std::string url);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_SRD_H_*/
