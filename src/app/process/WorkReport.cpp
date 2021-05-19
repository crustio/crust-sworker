#include "WorkReport.h"

extern sgx_enclave_id_t global_eid;
extern bool offline_chain_mode;

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: used to generate random waiting time to ensure that the reporting workload is not concentrated
 * @param seed -> Random seed
 * @return: wait time
 */
size_t get_random_wait_time(std::string seed)
{
    //[9  199]
    srand_string(seed);
    return (rand() % (REPORT_INTERVAL_BLCOK_NUMBER_UPPER_LIMIT - REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT + 1) + REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT - 1) * BLOCK_INTERVAL;
}

/**
 * @description: Judge whether need to exit while waiting
 * @param t -> Wait time
 * @return true for exiting
 */
bool wait_and_check_exit(size_t t)
{
    EnclaveData *ed = EnclaveData::get_instance();
    for (size_t i = 0; i < t; i++)
    {
        if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status())
        {
            p_log->info("Stop work report for exit...\n");
            return true;
        }
        sleep(1);
    }

    return false;
}

/**
 * @description: Check if there is enough height, send signed work report to chain
 */
void work_report_loop(void)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::Chain *p_chain = crust::Chain::get_instance();
    size_t target_block_height = REPORT_SLOT;
    size_t wr_wait_time = BLOCK_INTERVAL / 2;
    int stop_timeout = 10 * BLOCK_INTERVAL;
    int stop_tryout = stop_timeout / wr_wait_time;
    EnclaveData *ed = EnclaveData::get_instance();
    size_t cut_wait_time = 0;
    size_t wait_time = 0;

    // Set srand
    json::JSON id_json = json::JSON::Load(ed->get_enclave_id_info());

    // Generate target block height
    crust::BlockHeader block_header;
    if (!p_chain->get_block_header(block_header))
    {
        p_log->warn("Cannot get block header! Set target block height %d\n", target_block_height);
    }
    else
    {
        target_block_height = (block_header.number / REPORT_SLOT + 1) * REPORT_SLOT;
        p_log->info("Set target block height %d\n", target_block_height);
    }

    while (true)
    {
        if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status())
        {
            p_log->info("Stop work report for exit...\n");
            return;
        }

        crust::BlockHeader block_header;

        // ----- Report work report ----- //
        if (!p_chain->get_block_header(block_header))
        {
            p_log->warn("Cannot get block header!\n");
            goto loop;
        }

        if (block_header.number < target_block_height)
        {
            goto loop;
        }

        // Avoid A competing work-report with B
        if (UPGRADE_STATUS_STOP_WORKREPORT == ed->get_upgrade_status())
        {
            if (--stop_tryout < 0)
            {
                stop_tryout = stop_timeout / wr_wait_time;
            }
            else
            {
                goto loop;
            }
        }
        
        cut_wait_time = (block_header.number - (block_header.number / REPORT_SLOT) * REPORT_SLOT) * BLOCK_INTERVAL;

        wait_time = get_random_wait_time(id_json["pub_key"].ToString());
        if (cut_wait_time >= wait_time)
        {
            wait_time = 0;
        }
        else
        {
            wait_time = wait_time - cut_wait_time;
        }
        wait_time = std::max(wait_time, (size_t)REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT);

        p_log->info("It is estimated that the workload will be reported at the %lu block\n", block_header.number + (wait_time / BLOCK_INTERVAL) + 1);
        block_header.number = (block_header.number / REPORT_SLOT) * REPORT_SLOT;

        if (!offline_chain_mode)
        {
            if(wait_and_check_exit(wait_time))
            {
                return;
            }
        }
        else
        {
            if(wait_and_check_exit(10))
            {
                return;
            }
        }
        
        // Get confirmed block hash
        block_header.hash = p_chain->get_block_hash(block_header.number);
        if (block_header.hash == "" || block_header.hash == "0000000000000000000000000000000000000000000000000000000000000000")
        {
            p_log->warn("Get block hash failed");
            goto loop;
        }

        target_block_height = block_header.number + REPORT_SLOT;

        // Get signed validation report
        if (SGX_SUCCESS != (sgx_status = Ecall_gen_and_upload_work_report(global_eid, &crust_status,
                block_header.hash.c_str(), block_header.number)))
        {
            p_log->err("Get signed work report failed! Message:Invoke SGX API failed, error code:%lx!\n", sgx_status);
        }
        else if (CRUST_SUCCESS != crust_status)
        {
            switch (crust_status)
            {
            case CRUST_BLOCK_HEIGHT_EXPIRED:
                p_log->err("Block height has expired, please check your chain. SF:WRE\n");
                break;
            case CRUST_FIRST_WORK_REPORT_AFTER_REPORT:
                p_log->warn("Can't generate work report for the first time after restart, please wait for next slot.\n");
                break;
            case CRUST_SERVICE_UNAVAILABLE:
                p_log->err("IPFS is offline, please start ipfs or use delete interface to remove those files. SF:WRE\n");
                break;
            case CRUST_UPGRADE_IS_UPGRADING:
                p_log->info("Stop reporting work in this era, because of upgrading or exiting\n");
                break;
            case CRUST_SGX_SIGN_FAILED:
                p_log->err("Can't generate work report, SGX signed failed. SF:WRE");
                break;
            case CRUST_WORK_REPORT_NOT_VALIDATED:
                p_log->err("Hardware is too slow, validation has not been applied. SF:WRE\n");
                break;
            default:
                p_log->err("Get work report or upload failed. Error code: %x SF:WRE\n", crust_status);
            }
        }
    loop:
        if(wait_and_check_exit(wr_wait_time))
        {
            return;
        }

        if (offline_chain_mode)
        {
            p_chain->add_offline_block_height(REPORT_SLOT/20);
        }
    }
}
