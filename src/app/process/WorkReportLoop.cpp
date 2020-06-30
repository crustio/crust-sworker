#include "WorkReportLoop.h"

extern sgx_enclave_id_t global_eid;
extern std::string g_order_report_str;
crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: used to generate random waiting time to ensure that the reporting workload is not concentrated
 * @return: wait time
 */
size_t get_random_wait_time(std::string seed)
{
    unsigned int seed_number = 0;
    for(size i = 0; i < chain_address.size(); i++)
    {
        seed_number += chain_address[i];
    }
    srand(time(NULL)+seed_number);
    //[9  199]
    return (rand() % (REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT - REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT + 1) + REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT - 1) * BLOCK_INTERVAL;
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
    int order_report_interval = 0;

    while (true)
    {
        // ----- Report order report ----- //
        if (3 == order_report_interval)
        {
            if(SGX_SUCCESS != Ecall_get_signed_order_report(global_eid, &crust_status)
                || CRUST_SUCCESS != crust_status)
            {
                if (CRUST_REPORT_NO_ORDER_FILE != crust_status)
                {
                    p_log->err("Get signed order report failed! Error code: %x\n", crust_status);
                }
            }
            else
            {
                p_log->info("Get order report:%s\n", g_order_report_str.c_str());
            }
            g_order_report_str = "";
            order_report_interval = 0;
        }
        order_report_interval++;

        // ----- Report work report ----- //
        crust::BlockHeader *block_header = p_chain->get_block_header();
        if (block_header == NULL)
        {
            p_log->warn("Cannot get block header!\n");
            goto loop;
        }
        if (0 == block_header->number % REPORT_BLOCK_HEIGHT_BASE)
        {
            size_t wait_time = get_random_wait_time(Config::get_instance()->chain_address);
            p_log->info("It is estimated that the workload will be reported at the %lu block\n", block_header->number + (wait_time / BLOCK_INTERVAL) + 1);
            sleep(wait_time);

            // Get confirmed block hash
            block_header->hash = p_chain->get_block_hash(block_header->number);

            // Generate validation report and get report size
            if (Ecall_generate_work_report(global_eid, &crust_status, &report_len) != SGX_SUCCESS || crust_status != CRUST_SUCCESS)
            {
                p_log->err("Generate validation report failed! Error code: %x\n", crust_status);
                goto loop;
            }

            // Get signed validation report
            char *report = (char *)malloc(report_len);
            memset(report, 0, report_len);
            if (SGX_SUCCESS != Ecall_get_signed_work_report(global_eid, &crust_status,
                    block_header->hash.c_str(), block_header->number, &ecc_signature, report, report_len))
            {
                p_log->err("Get signed validation report failed!\n");
            }
            else
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    // Send signed validation report to crust chain
                    json::JSON work_json = json::JSON::Load(std::string(report));
                    char *p_hex_sig = hexstring_safe((const uint8_t *)&ecc_signature, sizeof(ecc_signature));
                    work_json["sig"] = std::string(p_hex_sig, sizeof(ecc_signature) * 2);
                    work_json["block_height"] = block_header->number;
                    work_json["block_hash"] = block_header->hash;
                    std::string work_str = work_json.dump();
                    p_log->info("Sign validation report successfully!\n%s\n", work_str.c_str());
                    if (p_hex_sig != NULL)
                    {
                        free(p_hex_sig);
                    }
                    // Delete space and line break
                    remove_char(work_str, '\\');
                    remove_char(work_str, '\n');
                    remove_char(work_str, ' ');
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
                else if (crust_status == CRUST_FIRST_WORK_REPORT_AFTER_REPORT)
                {
                    p_log->info("Can't generate work report for the first time after restart\n");
                }
                else
                {
                    p_log->err("Get signed validation report failed! Error code: %x\n", crust_status);
                }
            }
            free(report);
        }

    loop:
        sleep(BLOCK_INTERVAL / 2);
    }
}
