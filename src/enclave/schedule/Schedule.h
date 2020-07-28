#ifndef _CRUST_SCHEDULE_H_
#define _CRUST_SCHEDULE_H_

#include <map>
#include <set>
#include "sgx_thread.h"
#include "Enclave_t.h"

typedef enum _sched_process_t {
    SCHED_GET_WORKREPORT,
    SCHED_GET_ORDERREPORT,
    SCHED_SRD_CHECK_RESERVED,
    SCHED_CONFIRM_FILE,
    SCHED_DELETE_FILE,
    SCHED_SEAL,
    SCHED_UNSEAL,
    SCHED_VALIDATE_SRD,
    SCHED_VALIDATE_FILE,
    SCHED_SRD_CHANGE,
    SCHED_STORE_METADATA
} sched_process_t;

void sched_add(sched_process_t id);
void sched_del(sched_process_t id);
void sched_check(sched_process_t id, sgx_thread_mutex_t &mutex);

#endif /* !_CRUST_SCHEDULE_H_ */
