#ifndef _CRUST_SRD_H_
#define _CRUST_SRD_H_

#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "Workload.h"
#include "EUtils.h"
#include "PathHelper.h"
#include "Schedule.h"

#define SRD_MAX_PER_TURN 64

void srd_change();
void srd_increase(const char *path);
size_t srd_decrease(long change, std::map<std::string, std::set<size_t>> *srd_del_index_m = NULL);
void srd_update_metadata(const char *hashs, size_t hashs_len);
long get_srd_change();
void set_srd_change(long change);

#endif /* !_CRUST_SRD_H_ */
