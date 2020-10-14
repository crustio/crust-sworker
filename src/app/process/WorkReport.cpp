#include "WorkReport.h"

extern sgx_enclave_id_t global_eid;
extern bool offline_chain_mode;

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: used to generate random waiting time to ensure that the reporting workload is not concentrated
 * @return: wait time
 */
size_t get_random_wait_time(std::string seed)
{
    unsigned int seed_number = 0;
    for (size_t i = 0; i < seed.size(); i++)
    {
        seed_number += seed[i];
    }
    srand(time(NULL) + seed_number);
    //[9  199]
    return (rand() % (REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT - REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT + 1) + REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT - 1) * BLOCK_INTERVAL;
}

/**
 * @description: Check if there is enough height, send signed work report to chain
 */
void work_report_loop(void)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::Chain *p_chain = crust::Chain::get_instance();
    size_t offline_base_height = REPORT_BLOCK_HEIGHT_BASE;
    size_t target_block_height = REPORT_BLOCK_HEIGHT_BASE;

    // Generate target block height
    if (!offline_chain_mode)
    {
        crust::BlockHeader *block_header = p_chain->get_block_header();
        if (block_header == NULL)
        {
            p_log->warn("Cannot get block header! Set target block height %d\n", target_block_height);
        }
        else
        {
            target_block_height = (block_header->number / REPORT_BLOCK_HEIGHT_BASE + 1) * REPORT_BLOCK_HEIGHT_BASE;
            p_log->info("Set target block height %d\n", target_block_height);
        }
    }

    while (true)
    {
        if (UPGRADE_STATUS_EXIT == get_g_upgrade_status())
        {
            break;
        }

        // ----- Report work report ----- //
        crust::BlockHeader *block_header = NULL;
        if (!offline_chain_mode)
        {
            block_header = p_chain->get_block_header();
            if (block_header == NULL)
            {
                p_log->warn("Cannot get block header!\n");
                goto loop;
            }

            if (block_header->number < target_block_height)
            {
                goto loop;
            }

            block_header->number = (block_header->number / REPORT_BLOCK_HEIGHT_BASE) * REPORT_BLOCK_HEIGHT_BASE;

            size_t wait_time = get_random_wait_time(Config::get_instance()->chain_address + Config::get_instance()->base_url);
            p_log->info("It is estimated that the workload will be reported at the %lu block\n", block_header->number + (wait_time / BLOCK_INTERVAL) + 1);
            sleep(wait_time);

            // Get confirmed block hash
            block_header->hash = p_chain->get_block_hash(block_header->number);
            if (block_header->hash == "" || block_header->hash == "0000000000000000000000000000000000000000000000000000000000000000")
            {
                p_log->warn("Get block hash failed");
                goto loop;
            }

            target_block_height = block_header->number + REPORT_BLOCK_HEIGHT_BASE;
        }
        else
        {
            block_header = new crust::BlockHeader();
            block_header->hash = "1000000000000000000000000000000000000000000000000000000000000001";
            block_header->number = offline_base_height;
            offline_base_height += REPORT_BLOCK_HEIGHT_BASE;
            sleep(60);
        }

        // Get signed validation report
        if (SGX_SUCCESS != Ecall_get_signed_work_report(global_eid, &crust_status,
                block_header->hash.c_str(), block_header->number))
        {
            p_log->err("Get signed work report failed!\n");
        }
        else
        {
            if (CRUST_SUCCESS == crust_status)
            {
                // Send signed validation report to crust chain
                std::string work_str = get_g_enclave_workreport();
                p_log->info("Sign validation report successfully!\n%s\n", work_str.c_str());

                if (!offline_chain_mode)
                {
                    // Delete space and line break
                    remove_char(work_str, '\\');
                    remove_char(work_str, '\n');
                    remove_char(work_str, ' ');
                    if (!p_chain->post_sworker_work_report(work_str))
                    {
                        p_log->err("Send work report to crust chain failed!\n");
                    }
                    else
                    {
                        p_log->info("Send work report to crust chain successfully!\n");
                        report_add_callback();
                    }
                }
                else
                {
                    report_add_callback();
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
            else if (crust_status == CRUST_NO_KARST)
            {
                p_log->info("Can't generate work report. You have meaningful files, please start karst\n");
            }
            else
            {
                p_log->err("Get signed validation report failed! Error code: %x\n", crust_status);
            }
        }

    loop:
        sleep(BLOCK_INTERVAL / 2);
    }
}
