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
#include "EnclaveData.h"

// Indicates minimal srd reserved space
#define MIN_SRD_RESERVED 30
// Indicates maximal srd reserved space
#define DEFAULT_SRD_RESERVED 50
// Indicates srd upgrade timeout
#define SRD_UPGRADE_TIMEOUT 20

#define SRD_UPGRADE_INFO "srd_upgrade_info"
#define SRD_UPGRADE_INFO_TIMEOUT "timeout"
#define SRD_UPGRADE_INFO_SRD "srd"


#if defined(__cplusplus)
extern "C"
{
#endif

json::JSON get_increase_srd_info();
crust_status_t srd_change(long change);
void srd_check_reserved(void);
void set_reserved_space(size_t reserved);
size_t get_reserved_space();

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_SRD_H_*/
