#include "ReportTest.h"

extern sgx_thread_mutex_t g_gen_work_report;

/**
 * @description: Generate and upload signed validation report
 * @param block_hash (in) -> block hash
 * @param block_height (in) -> block height
 * @param wait_time -> Waiting time before upload
 * @param is_upgrading -> Is this upload kind of upgrade
 * @param locked -> Lock this upload or not
 * @return: sign status
 */
crust_status_t gen_and_upload_work_report_test(const char *block_hash, size_t block_height, long /*wait_time*/, bool is_upgrading, bool locked /*=true*/)
{
    SafeLock gen_sl(g_gen_work_report);
    if (locked)
    {
        gen_sl.lock();
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    // Wait indicated time

    // Generate work report
    if (CRUST_SUCCESS != (crust_status = gen_work_report(block_hash, block_height, is_upgrading)))
    {
        return crust_status;
    }

    // Upload work report
    ocall_upload_workreport(&crust_status);

    // Confirm work report result

    return crust_status;
}
