#include "WorkReportLoop.h"

extern sgx_enclave_id_t global_eid;
crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: used to generate random waiting time to ensure that the reporting workload is not concentrated
 * @return: wait time
 */
size_t get_random_wait_time(void)
{
    srand(time(NULL));
    return (rand() % REPORT_INTERVAL_BLCOK_NUMBER_LIMIT) * BLOCK_INTERVAL + BLOCK_INTERVAL / 2;
}

/**
 * @description: Check if there is enough height, send signed work report to chain
 * */
void *work_report_loop(void *)
{
    size_t report_len = 0;
    sgx_ec256_signature_t ecc_signature;
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::Chain *p_chain = crust::Chain::get_instance();

    while (true)
    {
        crust::BlockHeader *block_header = p_chain->get_block_header();
        if (block_header->number % REPORT_BLOCK_HEIGHT_BASE == 0)
        {
            size_t wait_time = get_random_wait_time();
            p_log->info("It is estimated that the workload will be reported at the %lu block\n", block_header->number + (wait_time / BLOCK_INTERVAL) + 1);
            sleep(wait_time);
            // Generate validation report and get report size
            if (ecall_generate_work_report(global_eid, &crust_status, &report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
            {
                p_log->err("Generate validation report failed! Error code: %x\n", crust_status);
                continue;
            }

            // Get signed validation report
            char *report = (char *)malloc(report_len);
            memset(report, 0, report_len);
            if (SGX_SUCCESS != ecall_get_signed_work_report(global_eid, &crust_status,
                    block_header->hash.c_str(), block_header->number, &ecc_signature, report, report_len))
            {
                p_log->err("Get signed validation report failed!\n");
            }
            else
            {
                if (crust_status == CRUST_SUCCESS)
                {
                    // Send signed validation report to crust chain
                    json::JSON work_json = json::JSON::Load(std::string(report));
                    work_json["sig"] = hexstring((const uint8_t *)&ecc_signature, sizeof(ecc_signature));
                    work_json["block_height"] = block_header->number;
                    work_json["block_hash"] = block_header->hash;
                    std::string work_str = work_json.dump();
                    p_log->info("Sign validation report successfully!\n%s\n", work_str.c_str());
                    // Delete space and line break
                    work_str.erase(std::remove(work_str.begin(), work_str.end(), ' '), work_str.end());
                    work_str.erase(std::remove(work_str.begin(), work_str.end(), '\n'), work_str.end());
                    if (!p_chain->post_tee_work_report(work_str))
                    {
                        p_log->err("Send work report to crust chain failed!\n");
                    }
                    else
                    {
                        p_log->info("Send work report to crust chain successfully!\n");
                    }
                }
                else if (crust_status == CRUST_BLOCK_HEIGHT_EXPIRED)
                {
                    p_log->info("Block height expired.\n");
                }
                else
                {
                    p_log->err("Get signed validation report failed! Error code: %x\n", crust_status);
                }
            }
            free(report);
        }
        else
        {
            p_log->debug("Block height: %lu is not enough!\n", block_header->number);
            sleep(BLOCK_INTERVAL / 2);
        }
    }
}
