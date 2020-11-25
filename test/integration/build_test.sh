#!/bin/bash
########## resource_h_test ##########
function resource_h_test()
{
    sed -i "/#define CRUST_INST_DIR/ c #define CRUST_INST_DIR      \"$testdir\" " $resource_h
}

########## enclave_cpp_test ##########
function enclave_cpp_test()
{
cat << EOF >>$enclave_cpp

void ecall_handle_report_result()
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    Workload::get_instance()->handle_report_result();
}

void ecall_validate_srd()
{
    sched_add(SCHED_VALIDATE_SRD);
    validate_srd();
    sched_del(SCHED_VALIDATE_SRD);
}

void ecall_validate_srd_real()
{
    sched_add(SCHED_VALIDATE_SRD);
    validate_srd_real();
    sched_del(SCHED_VALIDATE_SRD);
}

void ecall_validate_file()
{
    sched_add(SCHED_VALIDATE_FILE);
    validate_meaningful_file();
    sched_del(SCHED_VALIDATE_FILE);
}

void ecall_validate_file_real()
{
    sched_add(SCHED_VALIDATE_FILE);
    validate_meaningful_file_real();
    sched_del(SCHED_VALIDATE_FILE);
}

void ecall_validate_file_bench()
{
    sched_add(SCHED_VALIDATE_FILE);
    validate_meaningful_file_bench();
    sched_del(SCHED_VALIDATE_FILE);
}

void ecall_store_metadata()
{
    crust_status_t crust_status = CRUST_SUCCESS;
    if (CRUST_SUCCESS != (crust_status = id_store_metadata()))
    {
        log_err("Store enclave data failed!Error code:%lx\n", crust_status);
    }
}

void ecall_test_add_file(long file_num)
{
    Workload::get_instance()->test_add_file(file_num);
}

void ecall_test_valid_file(uint32_t file_num)
{
    Workload::get_instance()->test_valid_file(file_num);
}

void ecall_test_lost_file(uint32_t file_num)
{
    Workload::get_instance()->test_lost_file(file_num);
}

void ecall_test_delete_file(uint32_t file_num)
{
    Workload::get_instance()->test_delete_file(file_num);
}

void ecall_test_delete_file_unsafe(uint32_t file_num)
{
    Workload::get_instance()->test_delete_file_unsafe(file_num);
}

void ecall_srd_increase_test(const char* path)
{
    if (ENC_UPGRADE_STATUS_PROCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    sched_add(SCHED_SRD_CHANGE);
    srd_increase_test(path);
    sched_del(SCHED_SRD_CHANGE);
}

size_t ecall_srd_decrease_test(long change)
{
    sched_add(SCHED_SRD_CHANGE);
    size_t ret = srd_decrease_test(change);
    sched_del(SCHED_SRD_CHANGE);

    return ret;
}

void ecall_clean_file()
{
    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&g_checked_files_mutex);
    wl->checked_files.clear();
    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    sgx_thread_mutex_lock(&g_new_files_mutex);
    wl->new_files.clear();
    sgx_thread_mutex_unlock(&g_new_files_mutex);
}

crust_status_t ecall_get_file_info(const char *data)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    Workload *wl = Workload::get_instance();
    crust_status_t crust_status = CRUST_UNEXPECTED_ERROR;
    for (int i = wl->checked_files.size() - 1; i >= 0; i--)
    {
        if (wl->checked_files[i][FILE_HASH].ToString().compare(data) == 0)
        {
            std::string file_info_str = wl->checked_files[i].dump();
            remove_char(file_info_str, '\n');
            remove_char(file_info_str, '\\\\');
            remove_char(file_info_str, ' ');
            ocall_store_file_info(file_info_str.c_str());
            crust_status = CRUST_SUCCESS;
        }
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);

    return crust_status;
}
EOF

    sed -i '/using namespace std;/a extern sgx_thread_mutex_t g_checked_files_mutex;' $enclave_cpp
    sed -i '/using namespace std;/a extern sgx_thread_mutex_t g_new_files_mutex;' $enclave_cpp
}

########## enclave_edl_test ##########
function enclave_edl_test()
{
cat << EOF > $TMPFILE
        public void ecall_srd_increase_test([in, string] const char* path);
        public size_t ecall_srd_decrease_test(long change);  
		public void ecall_validate_srd();
		public void ecall_validate_srd_real();
		public void ecall_validate_file();
		public void ecall_validate_file_real();
		public void ecall_validate_file_bench();
		public void ecall_store_metadata();
        public void ecall_handle_report_result();

        public void ecall_test_add_file(long file_num);
        public void ecall_test_valid_file(uint32_t file_num);
        public void ecall_test_lost_file(uint32_t file_num);
        public void ecall_test_delete_file(uint32_t file_num);
        public void ecall_test_delete_file_unsafe(uint32_t file_num);
        public void ecall_clean_file();

        public crust_status_t ecall_get_file_info([in, string] const char *data);
EOF
    
    local pos=$(sed -n '/ecall_get_workload()/=' $enclave_edl)
    sed -i "$pos r $TMPFILE" $enclave_edl

    sed -i "/void ocall_store_upgrade_data(/a \\\t\\tvoid ocall_store_file_info([in, string] const char *info);" $enclave_edl
    sed -i "/void ocall_store_upgrade_data(/a \\\t\\tcrust_status_t ocall_get_file_block([in, string] const char *file_path, [out] unsigned char **p_file, [out] size_t *len);" $enclave_edl
    sed -i "/void ocall_store_upgrade_data(/a \\\t\\tcrust_status_t ocall_get_file_bench([in, string] const char *file_path, [out] unsigned char **p_file, [out] size_t *len);" $enclave_edl
        
}

########## ecalls_cpp_test ##########
function ecalls_cpp_test()
{
cat << EOF >$TMPFILE
	{"Ecall_validate_srd", 0},
	{"Ecall_validate_srd_real", 0},
	{"Ecall_validate_file", 0},
	{"Ecall_validate_file_real", 0},
	{"Ecall_validate_file_bench", 0},
	{"Ecall_store_metadata", 0},
    {"Ecall_handle_report_result", 0},
	{"Ecall_test_add_file", 1},
	{"Ecall_test_valid_file", 1},
	{"Ecall_test_valid_file", 1},
	{"Ecall_test_lost_file", 1},
	{"Ecall_test_delete_file", 1},
	{"Ecall_test_delete_file_unsafe", 1},
	{"Ecall_clean_file", 1},
	{"Ecall_get_file_info", 3},
    {"Ecall_srd_decrease_test", 1},
    {"Ecall_srd_increase_test", 2},
EOF
    local pos=$(sed -n '/{"Ecall_delete_file", 0},/=' $ecalls_cpp)
    sed -i "$pos r $TMPFILE" $ecalls_cpp

cat << EOF >>$ecalls_cpp

sgx_status_t Ecall_handle_report_result(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_handle_report_result(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_srd(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_srd_real(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_srd_real(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_file_real(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file_real(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_validate_file_bench(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_validate_file_bench(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_store_metadata(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_store_metadata(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_add_file(sgx_enclave_id_t eid, long file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_add_file(eid, file_num);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_valid_file(sgx_enclave_id_t eid, uint32_t file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_valid_file(eid, file_num);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_lost_file(sgx_enclave_id_t eid, uint32_t file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_lost_file(eid, file_num);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_delete_file(sgx_enclave_id_t eid, uint32_t file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_delete_file(eid, file_num);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_test_delete_file_unsafe(sgx_enclave_id_t eid, uint32_t file_num)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_test_delete_file_unsafe(eid, file_num);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_srd_increase_test(sgx_enclave_id_t eid, const char* path)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_increase_test(eid, path);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_srd_decrease_test(sgx_enclave_id_t eid, size_t *size, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_srd_decrease_test(eid, size, change);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_clean_file(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_clean_file(eid);

    free_enclave(__FUNCTION__);

    return ret;
}

sgx_status_t Ecall_get_file_info(sgx_enclave_id_t eid, crust_status_t *status, const char *data)
{
    sgx_status_t ret = SGX_SUCCESS;
    if (SGX_SUCCESS != (ret = try_get_enclave(__FUNCTION__)))
    {
        return ret;
    }

    ret = ecall_get_file_info(eid, status, data);

    free_enclave(__FUNCTION__);

    return ret;
}
EOF
}

########## ecalls_h_test ##########
function ecalls_h_test()
{
cat << EOF > $TMPFILE
sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_srd_real(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_file_real(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_file_bench(sgx_enclave_id_t eid);
sgx_status_t Ecall_store_metadata(sgx_enclave_id_t eid);
sgx_status_t Ecall_srd_increase_test(sgx_enclave_id_t eid, const char* path);
sgx_status_t Ecall_srd_decrease_test(sgx_enclave_id_t eid, size_t *size, size_t change);

sgx_status_t Ecall_handle_report_result(sgx_enclave_id_t eid);

sgx_status_t Ecall_test_add_file(sgx_enclave_id_t eid, long file_num);
sgx_status_t Ecall_test_valid_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_lost_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_delete_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_delete_file_unsafe(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_clean_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_get_file_info(sgx_enclave_id_t eid, crust_status_t *status, const char *data);
EOF

    local pos=$(sed -n '/sgx_status_t Ecall_get_workload(sgx_enclave_id_t eid);/=' $ecalls_h)
    sed -i "$((pos+1)) r $TMPFILE" $ecalls_h
}

########## process_cpp_test ##########
function process_cpp_test()
{
    local pos1=$(sed -n '/&work_report_loop/=' $process_cpp)
    sed -i "$((pos1-1)),$pos1 d" $process_cpp

    local pos2=$(sed -n '/&srd_check_reserved/=' $process_cpp)
    sed -i "$((pos2-1)),$pos2 d" $process_cpp

    local pos3=$(sed -n '/&main_loop/=' $process_cpp)
    sed -i "$((pos3-1)),$pos3 d" $process_cpp

    # Get block to gen upgrade data
    local pos4=$(sed -n '/crust::BlockHeader/=' $process_cpp)
    sed -i "$pos4,$((pos4+5)) d" $process_cpp
    sed -i "$((pos4-1)) a \\\t\t\tif (SGX_SUCCESS != (sgx_status = Ecall_gen_upgrade_data(global_eid, &crust_status, g_block_height+REPORT_BLOCK_HEIGHT_BASE+REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT)))" $process_cpp
    sed -i "/extern bool g_upgrade_flag;/ a extern size_t g_block_height;" $process_cpp
    pos4=$(sed -n '/if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status(/=' $process_cpp)
    sed -i "$((pos4+1)) a \\\t\t\tg_block_height += REPORT_BLOCK_HEIGHT_BASE;" $process_cpp
}

########## storage_cpp_test ##########
function storage_cpp_test()
{
cat << EOF >> $storage_cpp

/**
 * @description: Add delete meaningful file task
 * @param hash -> Meaningful file root hash
 */
void report_add_callback()
{
    sgx_enclave_id_t eid = global_eid;
    std::async(std::launch::async, [eid](){
        sgx_status_t sgx_status = SGX_SUCCESS;
        if (SGX_SUCCESS != (sgx_status = Ecall_handle_report_result(eid)))
        {
            p_log->err("Report result failed!Invoke SGX API failed!Error code:%lx\n", sgx_status);
        }
    });
}
EOF
}

########## storage_h_test ##########
function storage_h_test()
{
    local spos=$(sed -n "/void storage_add_delete(/=" $storage_h)
    sed -i "$spos a void report_add_callback();" $storage_h
}

########## apihandler_h_test ##########
function apihandler_h_test()
{
cat << EOF > $TMPFILE

        cur_path = urlendpoint->base + "/report/work";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            crust_status_t crust_status = CRUST_SUCCESS;
            uint8_t *hash_u = (uint8_t *)malloc(32);
            int tmp_int;
            res.result(200);
            for (uint32_t i = 0; i < 32 / sizeof(tmp_int); i++)
            {
                tmp_int = rand();
                memcpy(hash_u + i * sizeof(tmp_int), &tmp_int, sizeof(tmp_int));
            }
            std::string block_hash = hexstring_safe(hash_u, 32);
            json::JSON req_json = json::JSON::Load(req.body());
            size_t block_height = req_json["block_height"].ToInt();
            g_block_height = block_height;
            free(hash_u);
            if (SGX_SUCCESS != Ecall_gen_and_upload_work_report(global_eid, &crust_status,
                    block_hash.c_str(), block_height+REPORT_BLOCK_HEIGHT_BASE))
            {
                p_log->err("Get signed work report failed!\\n");
                res.result(400);
            }
            else
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    // Send signed validation report to crust chain
                    p_log->info("Send work report successfully!\\n");
                    std::string work_str = ed->get_enclave_workreport();
                    res.body() = work_str;
                }
                else if (crust_status == CRUST_BLOCK_HEIGHT_EXPIRED)
                {
                    p_log->info("Block height expired.\\n");
                    res.result(401);
                }
                else if (crust_status == CRUST_FIRST_WORK_REPORT_AFTER_REPORT)
                {
                    p_log->info("Can't generate work report for the first time after restart\\n");
                    res.result(402);
                }
                else
                {
                    p_log->err("Get signed validation report failed! Error code: %x\\n", crust_status);
                    res.result(403);
                }
            }
            goto getcleanup;
        }

        // --- Srd change API --- //
        cur_path = urlendpoint->base + "/report/result";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            // Confirm new file
            report_add_callback();
            ret_info = "Reporting result task has beening added!";
            res.body() = ret_info;

            goto getcleanup;
        }

        cur_path = urlendpoint->base + "/validate/srd";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_srd(global_eid);
        }

        cur_path = urlendpoint->base + "/validate/srd_real";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_srd_real(global_eid);
        }

        cur_path = urlendpoint->base + "/validate/file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_file(global_eid);
        }

        cur_path = urlendpoint->base + "/validate/file_real";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_file_real(global_eid);
        }

        cur_path = urlendpoint->base + "/validate/file_bench";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_file_bench(global_eid);
        }

        cur_path = urlendpoint->base + "/store_metadata";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_store_metadata(global_eid);
        }

        cur_path = urlendpoint->base + "/test/add_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            long file_num = req_json["file_num"].ToInt();
            Ecall_test_add_file(global_eid, file_num);
            res.body() = "Add file successfully!";
        }

        cur_path = urlendpoint->base + "/test/valid_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            long file_num = req_json["file_num"].ToInt();
            Ecall_test_valid_file(global_eid, file_num);
            res.body() = "Validate file successfully!";
        }

        cur_path = urlendpoint->base + "/test/lost_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_lost_file(global_eid, file_num);
            res.body() = "Lost file successfully!";
        }

        cur_path = urlendpoint->base + "/test/delete_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_delete_file(global_eid, file_num);
            res.body() = "Delete file successfully!";
        }

        cur_path = urlendpoint->base + "/test/delete_file_unsafe";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_delete_file_unsafe(global_eid, file_num);
            res.body() = "Delete file successfully!";
        }

        cur_path = urlendpoint->base + "/clean_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_clean_file(global_eid);
            res.body() = "Clean file successfully!";
        }

        cur_path = urlendpoint->base + "/file_info";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            std::string hash = req_json["hash"].ToString();
            crust_status_t crust_status = CRUST_SUCCESS;
            Ecall_get_file_info(global_eid, &crust_status, hash.c_str());
            if (CRUST_SUCCESS == crust_status)
            {
                res.body() = ed->get_file_info();
                res.result(200);
            }
            else
            {
                res.body() = "";
                res.result(400);
            }
        }
EOF

cat << EOF > $TMPFILE2

        cur_path = urlendpoint->base + "/srd/change_real";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            // Check input parameters
            json::JSON req_json = json::JSON::Load(req.body());
            change_srd_num = req_json["change"].ToInt();

            if (change_srd_num == 0)
            {
                p_log->info("Invalid change\n");
                res.body() = "Invalid change";
                res.result(402);
                goto end_change_srd_real;
            }
            else
            {
                // Start changing srd
				srd_change(change_srd_num);
            }
        end_change_srd_real:
            goto postcleanup;
        }

        cur_path = urlendpoint->base + "/srd/change_disk";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;

            // Change srd disk 
            json::JSON req_json = json::JSON::Load(req.body());
            json::JSON paths = req_json["paths"];
            std::string op = req_json["op"].ToString();
            json::JSON old_paths;
            for (int i = 0; i < p_config->srd_paths.size(); i++)
            {
                old_paths[p_config->srd_paths[i].ToString()] = 0;
            }
            if (paths.JSONType() != json::JSON::Class::Array)
            {
                ret_info = "Wrong paths structure!";
                p_log->err("%s\\n", ret_info.c_str());
                res.result(400);
                res.body() = ret_info;
                goto postcleanup;
            }
            else
            {
                if (op.compare("add") == 0)
                {
                    for (int i = 0; i < paths.size(); i++)
                    {
                        if (!old_paths.hasKey(paths[i].ToString()))
                        {
                            p_config->srd_paths.append(paths[i].ToString());
                        }
                    }
                }
                else if (op.compare("delete") == 0)
                {
                    bool deleted = false;
                    for (int i = 0; i < paths.size(); i++)
                    {
                        if (old_paths.hasKey(paths[i].ToString()))
                        {
                            old_paths.ObjectRange().object->erase(paths[i].ToString());
                            deleted = true;
                        }
                    }
                    if (deleted)
                    {
                        p_config->srd_paths = json::Array();
                        for (auto it = old_paths.ObjectRange().begin(); it != old_paths.ObjectRange().end(); it++)
                        {
                            p_config->srd_paths.append(it->first);
                        }
                    }
                }
                else
                {
                    ret_info = "Please indicate operation: add or delete!";
                    p_log->err("%s\\n", ret_info.c_str());
                    res.body() = ret_info;
                    goto postcleanup;
                }
                p_log->info("paths:%s\\n", p_config->srd_paths.dump().c_str());
                ret_info = "New disks paths have been changed successfully!";
                p_log->info("%s\\n", ret_info.c_str());
                res.body() = ret_info;
            }

            goto postcleanup;
        }
EOF

    # Add get signed workreport and signed order report API 
    local pos=$(sed -n '/getcleanup:/=' $apihandler_h)
    ((pos-=2))
    sed -i "$pos r $TMPFILE" $apihandler_h

    # Add srd change disk API
    pos=$(sed -n '/end_change_srd:/=' $apihandler_h)
    ((pos+=3))
    sed -i "$pos r $TMPFILE2" $apihandler_h

    # Upgrade start
    pos=$(sed -n '/crust::BlockHeader \*block_header =/=' $apihandler_h)
cat << EOF > $TMPFILE
            if (SGX_SUCCESS != (sgx_status = Ecall_enable_upgrade(global_eid, &crust_status, g_block_height+REPORT_BLOCK_HEIGHT_BASE+REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT)))
EOF
    sed -i "$((pos+7)) r $TMPFILE" $apihandler_h
    sed -i "$pos,$((pos+7)) d" $apihandler_h

    # Srd directly
    #pos=$(sed -n '/cur_path = urlendpoint->base + "\/srd\/change";/=' $apihandler_h)
    #sed -i "$((pos+5)),$((pos+22))d" $apihandler_h
    pos=$(sed -n '/Ecall_change_srd_task/=' $apihandler_h)
    sed -i "$((pos-2)),$((pos+24)) d " $apihandler_h
    sed -i "$((pos-2)) a \\\t\t\t\tsrd_change_test(change_srd_num);" $apihandler_h

    # Record block height
    sed -i "/long change_srd_num = 0;/ a size_t g_block_height = 0;" $apihandler_h
}

########## webserver_cpp_test ##########
function webserver_cpp_test()
{
    sed -i "/kill(g_webservice_pid,/ c //kill(g_webservice_pid," $webserver_cpp
}

########## enclavedata_cpp_test ##########
function enclavedata_cpp_test()
{
cat << EOF >> $data_cpp

void EnclaveData::set_enclave_workreport(std::string report)
{
    enclave_workreport = report;
}

std::string EnclaveData::get_enclave_workreport()
{
    return enclave_workreport;
}

void EnclaveData::set_file_info(std::string file_info)
{
    g_file_info = file_info;
}

std::string EnclaveData::get_file_info()
{
    return g_file_info;
}
EOF
}

########## enclavedata_h_test ##########
function enclavedata_h_test
{
    sed -i '/set_upgrade_status(/a void set_file_info(std::string file_info);' $data_h
    sed -i '/set_upgrade_status(/a void set_enclave_workreport(std::string report);' $data_h
    sed -i '/set_upgrade_status(/a std::string get_enclave_workreport();' $data_h
    sed -i '/set_file_info(/a std::string get_file_info();' $data_h
    sed -i "/std::mutex upgrade_status_mutex/a // File info\nstd::string g_file_info = \"\";" $data_h
    sed -i "/std::mutex upgrade_status_mutex/a // Work report\nstd::string enclave_workreport = \"\";" $data_h
}

function srd_h_test()
{
    sed -i "/size_t get_reserved_space();/ a void srd_change_test(long change);" $srd_h
}

function srd_cpp_test()
{
cat << EOF >> $srd_cpp
void srd_change_test(long change)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    Config *p_config = Config::get_instance();

    if (change > 0)
    {
        size_t true_increase = change;
        json::JSON disk_info_json = get_increase_srd_info(true_increase);
        // Add left change to next srd, if have
        if (change > (long)true_increase)
        {
            long left_srd_num = change - true_increase;
            long real_change = 0;
            if (SGX_SUCCESS != (sgx_status = Ecall_change_srd_task(global_eid, &crust_status, left_srd_num, &real_change)))
            {
                p_log->err("Set srd change failed!Invoke SGX api failed!Error code:%lx\n", sgx_status);
            }
            else
            {
                switch (crust_status)
                {
                case CRUST_SUCCESS:
                    p_log->debug("Add left srd task successfully!%ldG has been added, will be executed later.\n", real_change);
                    break;
                case CRUST_SRD_NUMBER_EXCEED:
                    p_log->warn("Add left srd task failed!Srd number has reached the upper limit!Real srd task is %ldG.\n", real_change);
                    break;
                default:
                    p_log->warn("Unexpected error has occurred!\n");
                }
            }
            //p_log->info("%ldG srd task left, add it to next srd.\n", left_srd_num);
        }
        if (true_increase == 0)
        {
            //p_log->warn("No available space for srd!\n");
            return;
        }
        // Print disk info
        auto disk_range = disk_info_json.ObjectRange();
        for (auto it = disk_range.begin(); it != disk_range.end(); it++)
        {
            p_log->info("Available space is %ldG disk in '%s', will use %ldG space\n", 
                    it->second["available"].ToInt(),
                    it->first.c_str(),
                    it->second["increased"].ToInt());
        }
        p_log->info("Start sealing %luG srd files (thread number: %d) ...\n", 
                true_increase, p_config->srd_thread_num);
        size_t increase_acc = true_increase;
        std::vector<std::string> srd_paths;
        for (auto it = disk_range.begin(); increase_acc > 0; )
        {
            if (it->second["increased"].ToInt() > 0)
            {
                srd_paths.push_back(it->first);
                it->second["increased"] = it->second["increased"].ToInt() - 1;
                increase_acc--;
            }
            if (++it == disk_range.end())
            {
                it = disk_range.begin();
            }
        }

        // ----- Do srd ----- //
        // Use omp parallel to seal srd disk, the number of threads is equal to the number of CPU cores
        ctpl::thread_pool pool(p_config->srd_thread_num);
        std::vector<std::shared_ptr<std::future<void>>> tasks_v;
        for (size_t i = 0; i < srd_paths.size(); i++)
        {
            std::string path = srd_paths[i];
            sgx_enclave_id_t eid = global_eid;
            //tasks_v.push_back(std::make_shared<std::future<void>>(std::async(std::launch::async, [eid, path](){
            tasks_v.push_back(std::make_shared<std::future<void>>(pool.push([eid, path](int /*id*/){
                if (SGX_SUCCESS != Ecall_srd_increase_test(eid, path.c_str()))
                {
                    // If failed, add current task to next turn
                    crust_status_t crust_status = CRUST_SUCCESS;
                    long real_change = 0;
                    Ecall_change_srd_task(global_eid, &crust_status, 1, &real_change);
                }
            })));
        }
        // Wait for srd task
        for (auto it : tasks_v)
        {
            try 
            {
                it->get();
            }
            catch (std::exception &e)
            {
                p_log->err("Catch exception:");
                std::cout << e.what() << std::endl;
            }
        }

        p_config->change_srd_capacity(true_increase);
        p_log->info("Increase %dG srd files success, the srd workload will change gradually in next validation loops\n", true_increase);
    }
    else if (change < 0)
    {
        size_t true_decrease = -change;
        size_t ret_size = 0;
        size_t total_decrease_size = 0;
        json::JSON disk_decrease = get_decrease_srd_info(true_decrease);
        if (true_decrease == 0)
        {
            p_log->warn("No srd space to delete!\n");
            return;
        }
        p_log->info("True decreased space is:%d\n", true_decrease);
        Ecall_srd_decrease_test(global_eid, &ret_size, true_decrease);
        total_decrease_size = ret_size;
        p_config->change_srd_capacity(total_decrease_size);
        p_log->info("Decrease %luG srd files success, the srd workload will change in next validation loop\n", total_decrease_size);
    }
}
EOF
}

########## enc_report_cpp_test ##########
function enc_report_cpp_test()
{
    local spos=$(sed -n '/crust_status_t gen_work_report(/=' $enclave_report_cpp)
    sed -i "$((spos+15)),$((spos+19)) d" $enclave_report_cpp

    sed -i "/ocall_usleep(/ c //ocall_usleep(" $enclave_report_cpp
    sed -i "/Workload::get_instance()->handle_report_result(/ c //Workload::get_instance()->handle_report_result(" $enclave_report_cpp
}

########## enc_validate_h_test ##########
function enc_validate_h_test()
{
    sed -i "/void validate_meaningful_file(/ a void validate_meaningful_file_real();" $enclave_validate_h
    sed -i "/void validate_meaningful_file(/ a void validate_meaningful_file_bench();" $enclave_validate_h
    sed -i "/void validate_meaningful_file(/ a void validate_srd_real();" $enclave_validate_h
}

########## enc_validate_cpp_test ##########
function enc_validate_cpp_test()
{
    sed -i -e "s/ocall_validate_init(/\/\/ocall_validate_init(/g" -e "s/ocall_validate_close(/\/\/ocall_validate_close(/g" $enclave_validate_cpp
    local spos=$(sed -n "/dir_path = chose_entry->first;/=" $enclave_validate_cpp)
    local epos=$(sed -n "/\/\/ Compare leaf data/=" $enclave_validate_cpp)
    sed -i "$spos,$((epos+7)) d" $enclave_validate_cpp

    spos=$(sed -n '/Get block data/=' $enclave_validate_cpp)
    epos=$(sed -n '/free(leaf_hash_u);/=' $enclave_validate_cpp | tail -n 1)
    sed -i "$spos,$epos d" $enclave_validate_cpp

    ### Delete old validate srd func
    spos=$(sed -n '/void validate_srd()/=' $enclave_validate_cpp)
    epos=$(sed -n "$spos,$ {/^}/=}" $enclave_validate_cpp | head -n 1)
    sed -i "$spos,$epos d" $enclave_validate_cpp

cat << EOF >>$enclave_validate_cpp

void validate_srd()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&g_srd_mutex);

    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    size_t srd_validate_num = std::max((size_t)(srd_total_num * SRD_VALIDATE_RATE), (size_t)SRD_VALIDATE_MIN_NUM);

    log_debug("validate srd start, num:%d\n", srd_validate_num);
    // Randomly choose validate srd files
    std::set<std::pair<uint32_t, uint32_t>> validate_srd_idx_s;
    std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry;
    if (srd_validate_num < srd_total_num)
    {
        uint32_t rand_val;
        uint32_t rand_idx = 0;
        std::pair<uint32_t, uint32_t> p_chose;
        for (size_t i = 0; i < srd_validate_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            chose_entry = wl->srd_path2hashs_m.begin();
            uint32_t path_idx = rand_val % wl->srd_path2hashs_m.size();
            for (uint32_t i = 0; i < path_idx; i++)
            {
                chose_entry++;
            }
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_idx = rand_val % chose_entry->second.size();
            p_chose = std::make_pair(path_idx, rand_idx);
            validate_srd_idx_s.insert(p_chose);
        }
    }
    else
    {
        int i = 0;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++, i++)
        {
            for (size_t j = 0; j < it->second.size(); j++)
            {
                validate_srd_idx_s.insert(make_pair(i, j));
            }
        }
    }

    // ----- Validate SRD ----- //
    std::map<std::string, std::set<size_t>> del_path2idx_m;
    for (auto srd_idx : validate_srd_idx_s)
    {
        // Check sched func
        sched_check(SCHED_VALIDATE_SRD, g_srd_mutex);
        // If srd has been deleted, go to next check
        std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry = wl->srd_path2hashs_m.begin();
        for (size_t i = 0; i < srd_idx.first && chose_entry != wl->srd_path2hashs_m.end(); i++)
        {
            chose_entry++;
        }
        if (chose_entry == wl->srd_path2hashs_m.end() || srd_idx.second >= chose_entry->second.size())
        {
            continue;
        }

        uint8_t *m_hashs_org = NULL;
        uint8_t *m_hashs = NULL;
        size_t m_hashs_size = 0;
        sgx_sha256_hash_t m_hashs_sha256;
        size_t srd_block_index = 0;
        std::string leaf_path;
        uint8_t *leaf_data = NULL;
        size_t leaf_data_len = 0;
        sgx_sha256_hash_t leaf_hash;
        std::string hex_g_hash;
        std::string dir_path;
        std::string g_path;

        dir_path = chose_entry->first;
        uint8_t *p_g_hash = chose_entry->second[srd_idx.second];

        // Get g_hash corresponding path
        hex_g_hash = hexstring_safe(p_g_hash, HASH_LENGTH);
        g_path = std::string(dir_path).append("/").append(hexstring_safe(p_g_hash, HASH_LENGTH));

        // Get M hashs
        ocall_get_file_bench(&crust_status, get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
        if (m_hashs_org == NULL)
        {
            log_err("Get m hashs file failed in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        m_hashs = (uint8_t *)enc_malloc(m_hashs_size);
        if (m_hashs == NULL)
        {
            log_err("Malloc memory failed!\n");
            goto nextloop;
        }
        memset(m_hashs, 0, m_hashs_size);
        memcpy(m_hashs, m_hashs_org, m_hashs_size);

        // Compare M hashs
        sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_sha256);
        if (memcmp(p_g_hash, m_hashs_sha256, HASH_LENGTH)) {}

        // Get leaf data
        uint32_t rand_val;
        sgx_read_rand((uint8_t*)&rand_val, 4);
        srd_block_index = rand_val % SRD_RAND_DATA_NUM;
        leaf_path = get_leaf_path(g_path.c_str(), srd_block_index, m_hashs + srd_block_index * 32);
        ocall_get_file_bench(&crust_status, leaf_path.c_str(), &leaf_data, &leaf_data_len);

        if (leaf_data == NULL)
        {
            log_err("Get leaf file failed in '%s'.\n", hexstring_safe(p_g_hash, HASH_LENGTH).c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        // Compare leaf data
        sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_hash);
        if (memcmp(m_hashs + srd_block_index * 32, leaf_hash, HASH_LENGTH)) {}


    nextloop:
        if (m_hashs != NULL)
        {
            free(m_hashs);
        }
    }
    log_debug("validate srd end, num:%d\n", srd_validate_num);


    sgx_thread_mutex_unlock(&g_srd_mutex);
}

void validate_srd_real()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&g_srd_mutex);

    size_t srd_num_threshold = 1 / SRD_VALIDATE_RATE * SRD_VALIDATE_MIN_NUM;
    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    size_t srd_validate_num = srd_total_num * SRD_VALIDATE_RATE;
    size_t srd_validate_failed_num = 0;
    
    // Caculate srd validated variable
    if (srd_total_num >= srd_num_threshold)
    {
        srd_validate_num = srd_total_num * SRD_VALIDATE_RATE;
    }
    else
    {
        if (srd_total_num < SRD_VALIDATE_MIN_NUM)
        {
            srd_validate_num = srd_total_num;
        }
        else
        {
            srd_validate_num = SRD_VALIDATE_MIN_NUM;
        }
    }

    // Randomly choose validate srd files
    std::set<std::pair<uint32_t, uint32_t>> validate_srd_idx_s;
    std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry;
    if (srd_validate_num < srd_total_num)
    {
        uint32_t rand_val;
        uint32_t rand_idx = 0;
        std::pair<uint32_t, uint32_t> p_chose;
        for (size_t i = 0; i < srd_validate_num; i++)
        {
            sgx_read_rand((uint8_t *)&rand_val, 4);
            chose_entry = wl->srd_path2hashs_m.begin();
            uint32_t path_idx = rand_val % wl->srd_path2hashs_m.size();
            for (uint32_t i = 0; i < path_idx; i++)
            {
                chose_entry++;
            }
            sgx_read_rand((uint8_t *)&rand_val, 4);
            rand_idx = rand_val % chose_entry->second.size();
            p_chose = std::make_pair(path_idx, rand_idx);
            validate_srd_idx_s.insert(p_chose);
        }
    }
    else
    {
        int i = 0;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++, i++)
        {
            for (size_t j = 0; j < it->second.size(); j++)
            {
                validate_srd_idx_s.insert(make_pair(i, j));
            }
        }
    }

    // ----- Validate SRD ----- //
    std::map<std::string, std::set<size_t>> del_path2idx_m;
    for (auto srd_idx : validate_srd_idx_s)
    {
        // Check sched func
        sched_check(SCHED_VALIDATE_SRD, g_srd_mutex);
        // If srd has been deleted, go to next check
        std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry = wl->srd_path2hashs_m.begin();
        for (size_t i = 0; i < srd_idx.first && chose_entry != wl->srd_path2hashs_m.end(); i++)
        {
            chose_entry++;
        }
        if (chose_entry == wl->srd_path2hashs_m.end() || srd_idx.second >= chose_entry->second.size())
        {
            continue;
        }

        uint8_t *m_hashs_org = NULL;
        uint8_t *m_hashs = NULL;
        size_t m_hashs_size = 0;
        sgx_sha256_hash_t m_hashs_sha256;
        size_t srd_block_index = 0;
        std::string leaf_path;
        uint8_t *leaf_data = NULL;
        size_t leaf_data_len = 0;
        sgx_sha256_hash_t leaf_hash;
        std::string hex_g_hash;
        std::string dir_path;
        std::string g_path;

        dir_path = chose_entry->first;
        uint8_t *p_g_hash = chose_entry->second[srd_idx.second];

        // Get g_hash corresponding path
        hex_g_hash = hexstring_safe(p_g_hash, HASH_LENGTH);
        g_path = std::string(dir_path).append("/").append(hexstring_safe(p_g_hash, HASH_LENGTH));

        // Get M hashs
        ocall_get_file(&crust_status, get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
        if (m_hashs_org == NULL)
        {
            log_err("Get m hashs file failed in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        m_hashs = (uint8_t *)enc_malloc(m_hashs_size);
        if (m_hashs == NULL)
        {
            log_err("Malloc memory failed!\n");
            goto nextloop;
        }
        memset(m_hashs, 0, m_hashs_size);
        memcpy(m_hashs, m_hashs_org, m_hashs_size);

        // Compare M hashs
        sgx_sha256_msg(m_hashs, m_hashs_size, &m_hashs_sha256);
        if (memcmp(p_g_hash, m_hashs_sha256, HASH_LENGTH) != 0)
        {
            log_err("Wrong m hashs file in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        // Get leaf data
        uint32_t rand_val;
        sgx_read_rand((uint8_t*)&rand_val, 4);
        srd_block_index = rand_val % SRD_RAND_DATA_NUM;
        leaf_path = get_leaf_path(g_path.c_str(), srd_block_index, m_hashs + srd_block_index * 32);
        ocall_get_file(&crust_status, leaf_path.c_str(), &leaf_data, &leaf_data_len);

        if (leaf_data == NULL)
        {
            log_err("Get leaf file failed in '%s'.\n", hexstring_safe(p_g_hash, HASH_LENGTH).c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }

        // Compare leaf data
        sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_hash);
        if (memcmp(m_hashs + srd_block_index * 32, leaf_hash, HASH_LENGTH) != 0)
        {
            log_err("Wrong leaf data hash in '%s'.\n", hex_g_hash.c_str());
            del_path2idx_m[dir_path].insert(srd_idx.second);
            goto nextloop;
        }


    nextloop:
        if (m_hashs != NULL)
        {
            free(m_hashs);
        }
    }

    // Delete indicated punished files
    for (auto it : del_path2idx_m)
    {
        srd_validate_failed_num += it.second.size();
    }
    srd_random_delete(SRD_PUNISH_FACTOR * srd_validate_failed_num, &del_path2idx_m);

    sgx_thread_mutex_unlock(&g_srd_mutex);
}

void validate_meaningful_file_bench()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Lock wl->checked_files
    SafeLock cf_lock(g_checked_files_mutex);
    cf_lock.lock();

    // Add new file to validate
    sgx_thread_mutex_lock(&g_new_files_mutex);
    if (wl->new_files.size() > 0)
    {
        // Insert new files to checked files
        wl->checked_files.insert(wl->checked_files.end(), wl->new_files.begin(), wl->new_files.end());
        // Clear new files
        wl->new_files.clear();
    }
    sgx_thread_mutex_unlock(&g_new_files_mutex);

    // Get to be checked files indexes
    size_t check_file_num = std::max((size_t)(wl->checked_files.size() * MEANINGFUL_VALIDATE_RATE), (size_t)MEANINGFUL_VALIDATE_MIN_NUM);
    std::vector<uint32_t> file_idx_v;
    uint32_t rand_val;
    size_t rand_index = 0;
    for (size_t i = 0; i < check_file_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        rand_index = rand_val % wl->checked_files.size();
        file_idx_v.push_back(rand_index);
    }

    log_debug("validate file start, num:%d\n", check_file_num);
    // ----- Randomly check file block ----- //
    // TODO: Do we allow to store duplicated files?
    // Used to indicate which meaningful file status has been changed
    std::unordered_map<size_t, bool> changed_idx2lost_um;
    for (auto file_idx : file_idx_v)
    {
        // Check race
        sched_check(SCHED_VALIDATE_FILE, g_checked_files_mutex);
        // If file has been deleted, go to next check
        if (file_idx >= wl->checked_files.size())
        {
            continue;
        }

        // If new file hasn't been confirmed, skip this validation
        auto status = &wl->checked_files[file_idx][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_UNCONFIRMED 
                || status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
        {
            continue;
        }

        file_idx = 0;
        std::string root_hash = wl->checked_files[file_idx][FILE_HASH].ToString();
        size_t file_block_num = wl->checked_files[file_idx][FILE_BLOCK_NUM].ToInt();
        // Get tree string
        crust_status = persist_get_unsafe(root_hash, &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status || p_data == NULL)
        {
            log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_hash.c_str());
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }
        // Validate merkle tree
        std::string tree_str(reinterpret_cast<char *>(p_data), data_len);
        if (p_data != NULL)
        {
            free(p_data);
            p_data = NULL;
        }
        json::JSON tree_json = json::JSON::Load(tree_str);
        if (root_hash.compare(tree_json[FILE_HASH].ToString()) != 0 || CRUST_SUCCESS != validate_merkletree_json(tree_json))
        {
            log_err("File:%s merkle tree is not valid!\n", root_hash.c_str());
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }

        // ----- Validate MerkleTree ----- //
        // Note: should store serialized tree structure as "links_num":x,"hash":"xxxxx","size":
        // be careful about "links_num", "hash" and "size" sequence
        size_t spos, epos;
        spos = epos = 0;
        std::string stag = "\"" MT_LINKS_NUM "\":0,\"" MT_HASH "\":\"";
        std::string etag = "\",\"" MT_SIZE "\"";
        // Get to be checked block index
        std::set<size_t> block_idx_s;
        for (size_t i = 0; i < MEANINGFUL_VALIDATE_MIN_BLOCK_NUM && i < file_block_num; i++)
        {
            size_t tmp_idx = 0;
            sgx_read_rand((uint8_t *)&rand_val, 4);
            tmp_idx = rand_val % file_block_num;
            if (block_idx_s.find(tmp_idx) == block_idx_s.end())
            {
                block_idx_s.insert(tmp_idx);
            }
        }
        // Do check
        size_t cur_block_idx = 0;
        bool checked_ret = true;
        for (auto check_block_idx : block_idx_s)
        {
            // Get leaf node position
            do
            {
                spos = tree_str.find(stag, spos);
                if (spos == tree_str.npos)
                {
                    break;
                }
                spos += stag.size();
            } while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos || (epos = tree_str.find(etag, spos)) == tree_str.npos)
            {
                log_err("Find file(%s) leaf node failed!node index:%ld\n", root_hash.c_str(), check_block_idx);
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                break;
            }
            // Get block data
            std::string leaf_hash = tree_str.substr(spos, epos - spos);
            std::string block_str = root_hash + "/" + std::to_string(check_block_idx).append("_").append(leaf_hash);
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            ocall_get_file_block(&crust_status, block_str.c_str(), &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status || p_sealed_data == NULL || sealed_data_size == 0)
            {
                if (CRUST_VALIDATE_KARST_OFFLINE == crust_status)
                {
                    log_err("Get file(%s) block:%ld failed!\n", root_hash.c_str(), check_block_idx);
                    wl->set_report_file_flag(false);
                    return;
                }
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                break;
            }
            // Validate hash
            sgx_sha256_hash_t got_hash;
            sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
            uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
            if (leaf_hash_u == NULL)
            {
                log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
                continue;
            }
            if (memcmp(leaf_hash_u, got_hash, HASH_LENGTH) != 0)
            {
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    log_err("File(%s) Index:%ld block hash is not expected!\n", root_hash.c_str(), check_block_idx);
                    //log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                    //log_err("Org hash : %s\n", leaf_hash.c_str());
                    status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
        // Set lost file back
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST && checked_ret)
        {
            status->set_char(CURRENT_STATUS, FILE_STATUS_VALID);
            changed_idx2lost_um[file_idx] = false;
        }
    }

    // Change file status
    if (changed_idx2lost_um.size() > 0)
    {
        for (auto it : changed_idx2lost_um)
        {
            char old_status_c = (it.second ? FILE_STATUS_VALID : FILE_STATUS_LOST);
            char cur_status_c = wl->checked_files[it.first][FILE_STATUS].get_char(CURRENT_STATUS);
            std::string old_status = (it.second ? g_file_status[FILE_STATUS_VALID] : g_file_status[FILE_STATUS_LOST]);
            std::string cur_status = g_file_status[wl->checked_files[it.first][FILE_STATUS].get_char(CURRENT_STATUS)];
            log_info("File status changed, hash: %s status: %s -> %s\n",
                    wl->checked_files[it.first][FILE_HASH].ToString().c_str(),
                    old_status.c_str(),
                    cur_status.c_str());
            wl->set_wl_spec(cur_status_c, old_status_c, wl->checked_files[it.first][FILE_OLD_SIZE].ToInt());
        }
    }
    log_debug("validate file end, num:%d\n", check_file_num);

    // Unlock wl->checked_files
    cf_lock.unlock();
}

void validate_meaningful_file_real()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    uint8_t *p_data = NULL;
    size_t data_len = 0;
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();

    // Lock wl->checked_files
    SafeLock cf_lock(g_checked_files_mutex);
    cf_lock.lock();

    // Add new file to validate
    sgx_thread_mutex_lock(&g_new_files_mutex);
    if (wl->new_files.size() > 0)
    {
        // Insert new files to checked files
        wl->checked_files.insert(wl->checked_files.end(), wl->new_files.begin(), wl->new_files.end());
        // Clear new files
        wl->new_files.clear();
    }
    sgx_thread_mutex_unlock(&g_new_files_mutex);

    // Get to be checked files indexes
    size_t check_file_num = std::max((size_t)(wl->checked_files.size() * MEANINGFUL_VALIDATE_RATE), (size_t)MEANINGFUL_VALIDATE_MIN_NUM);
    std::vector<uint32_t> file_idx_v;
    uint32_t rand_val;
    size_t rand_index = 0;
    for (size_t i = 0; i < check_file_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        rand_index = rand_val % wl->checked_files.size();
        file_idx_v.push_back(rand_index);
    }

    // ----- Randomly check file block ----- //
    // TODO: Do we allow to store duplicated files?
    // Used to indicate which meaningful file status has been changed
    std::unordered_map<size_t, bool> changed_idx2lost_um;
    for (auto file_idx : file_idx_v)
    {
        // Check race
        sched_check(SCHED_VALIDATE_FILE, g_checked_files_mutex);
        // If file has been deleted, go to next check
        if (file_idx >= wl->checked_files.size())
        {
            continue;
        }

        // If new file hasn't been confirmed, skip this validation
        auto status = &wl->checked_files[file_idx][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_UNCONFIRMED 
                || status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
        {
            continue;
        }

        std::string root_hash = wl->checked_files[file_idx][FILE_HASH].ToString();
        size_t file_block_num = wl->checked_files[file_idx][FILE_BLOCK_NUM].ToInt();
        // Get tree string
        crust_status = persist_get_unsafe(root_hash, &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status || p_data == NULL)
        {
            log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_hash.c_str());
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }
        // Validate merkle tree
        std::string tree_str(reinterpret_cast<char *>(p_data), data_len);
        if (p_data != NULL)
        {
            free(p_data);
            p_data = NULL;
        }
        json::JSON tree_json = json::JSON::Load(tree_str);
        if (root_hash.compare(tree_json[FILE_HASH].ToString()) != 0 || CRUST_SUCCESS != validate_merkletree_json(tree_json))
        {
            log_err("File:%s merkle tree is not valid!\n", root_hash.c_str());
            if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                changed_idx2lost_um[file_idx] = true;
            }
            continue;
        }

        // ----- Validate MerkleTree ----- //
        // Note: should store serialized tree structure as "links_num":x,"hash":"xxxxx","size":
        // be careful about "links_num", "hash" and "size" sequence
        size_t spos, epos;
        spos = epos = 0;
        std::string stag = "\\"" MT_LINKS_NUM "\\":0,\\"" MT_HASH "\\":\\"";
        std::string etag = "\\",\\"" MT_SIZE "\\"";
        // Get to be checked block index
        std::set<size_t> block_idx_s;
        for (size_t i = 0; i < MEANINGFUL_VALIDATE_MIN_BLOCK_NUM && i < file_block_num; i++)
        {
            size_t tmp_idx = 0;
            sgx_read_rand((uint8_t *)&rand_val, 4);
            tmp_idx = rand_val % file_block_num;
            if (block_idx_s.find(tmp_idx) == block_idx_s.end())
            {
                block_idx_s.insert(tmp_idx);
            }
        }
        // Do check
        size_t cur_block_idx = 0;
        bool checked_ret = true;
        for (auto check_block_idx : block_idx_s)
        {
            // Get leaf node position
            do
            {
                spos = tree_str.find(stag, spos);
                if (spos == tree_str.npos)
                {
                    break;
                }
                spos += stag.size();
            } while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos || (epos = tree_str.find(etag, spos)) == tree_str.npos)
            {
                log_err("Find file(%s) leaf node failed!node index:%ld\n", root_hash.c_str(), check_block_idx);
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                break;
            }
            // Get block data
            std::string leaf_hash = tree_str.substr(spos, epos - spos);
            std::string block_str = root_hash + "/" + std::to_string(check_block_idx).append("_").append(leaf_hash);
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            ocall_get_file_block(&crust_status, block_str.c_str(), &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status || p_sealed_data == NULL || sealed_data_size == 0)
            {
                if (CRUST_VALIDATE_KARST_OFFLINE == crust_status)
                {
                    log_err("Get file(%s) block:%ld failed!\n", root_hash.c_str(), check_block_idx);
                    wl->set_report_file_flag(false);
                    return;
                }
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                break;
            }
            // Validate hash
            sgx_sha256_hash_t got_hash;
            sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
            uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
            if (leaf_hash_u == NULL)
            {
                log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
                continue;
            }
            if (memcmp(leaf_hash_u, got_hash, HASH_LENGTH) != 0)
            {
                if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    log_err("File(%s) Index:%ld block hash is not expected!\n", root_hash.c_str(), check_block_idx);
                    //log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                    //log_err("Org hash : %s\n", leaf_hash.c_str());
                    status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
                    changed_idx2lost_um[file_idx] = true;
                }
                checked_ret = false;
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
        // Set lost file back
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST && checked_ret)
        {
            status->set_char(CURRENT_STATUS, FILE_STATUS_VALID);
            changed_idx2lost_um[file_idx] = false;
        }
    }

    // Change file status
    if (changed_idx2lost_um.size() > 0)
    {
        for (auto it : changed_idx2lost_um)
        {
            char old_status_c = (it.second ? FILE_STATUS_VALID : FILE_STATUS_LOST);
            char cur_status_c = wl->checked_files[it.first][FILE_STATUS].get_char(CURRENT_STATUS);
            std::string old_status = (it.second ? g_file_status[FILE_STATUS_VALID] : g_file_status[FILE_STATUS_LOST]);
            std::string cur_status = g_file_status[wl->checked_files[it.first][FILE_STATUS].get_char(CURRENT_STATUS)];
            log_info("File status changed, hash: %s status: %s -> %s\n",
                    wl->checked_files[it.first][FILE_HASH].ToString().c_str(),
                    old_status.c_str(),
                    cur_status.c_str());
            wl->set_wl_spec(cur_status_c, old_status_c, wl->checked_files[it.first][FILE_OLD_SIZE].ToInt());
        }
    }

    // Unlock wl->checked_files
    cf_lock.unlock();
}
EOF
}

########## enc_srd_h_test ##########
function enc_srd_h_test()
{
    sed -i "/^#define SRD_MAX_PER_TURN 64/ c #define SRD_MAX_PER_TURN 1000" $enclave_srd_h
    sed -i "/crust_status_t change_srd_task(/ a size_t srd_decrease_test(long change, std::map<std::string, std::set<size_t>> *srd_del_index_m = NULL);" $enclave_srd_h
    sed -i "/crust_status_t change_srd_task(/ a void srd_increase_test(const char *path);" $enclave_srd_h
}

########## enc_srd_cpp_test ##########
function enc_srd_cpp_test()
{
cat << EOF >> $enclave_srd_cpp

void srd_increase_test(const char *path)
{
    Workload *wl = Workload::get_instance();
    std::string path_str(path);

    // Generate base random data
    do
    {
        if (g_base_rand_buffer == NULL)
        {
            sgx_thread_mutex_lock(&g_base_rand_buffer_mutex);
            if (g_base_rand_buffer != NULL)
            {
                sgx_thread_mutex_unlock(&g_base_rand_buffer_mutex);
                break;
            }
            g_base_rand_buffer = (uint8_t *)enc_malloc(SRD_RAND_DATA_LENGTH);
            if (g_base_rand_buffer == NULL)
            {
                log_err("Malloc memory failed!\n");
                sgx_thread_mutex_unlock(&g_base_rand_buffer_mutex);
                return;
            }
            memset(g_base_rand_buffer, 0, SRD_RAND_DATA_LENGTH);
            sgx_read_rand(g_base_rand_buffer, sizeof(g_base_rand_buffer));
            sgx_thread_mutex_unlock(&g_base_rand_buffer_mutex);
        }
    } while (0);

    // Generate current G hash index
    size_t now_index = 0;
    sgx_read_rand((unsigned char *)&now_index, 8);

    // ----- Generate srd file ----- //

    // Generate all M hashs and store file to disk
    unsigned char *hashs = (unsigned char*)enc_malloc(SRD_RAND_DATA_NUM * HASH_LENGTH);
    if (hashs == NULL)
    {
        log_err("Malloc memory failed!\n");
        return;
    }

    // Generate G hashs
    sgx_sha256_hash_t g_out_hash256;
    sgx_sha256_msg(hashs, SRD_RAND_DATA_NUM * HASH_LENGTH, &g_out_hash256);
    free(hashs);

    // Get g hash
    uint8_t *p_hash_u = (uint8_t *)enc_malloc(HASH_LENGTH);
    if (p_hash_u == NULL)
    {
        log_info("Seal random data failed! Malloc memory failed!\n");
        return;
    }
    memset(p_hash_u, 0, HASH_LENGTH);
    memcpy(p_hash_u, g_out_hash256, HASH_LENGTH);

    // ----- Update srd_path2hashs_m ----- //
    std::string hex_g_hash = hexstring_safe(p_hash_u, HASH_LENGTH);
    if (hex_g_hash.compare("") == 0)
    {
        log_err("Hexstring failed!\n");
        return;
    }
    // Add new g_hash to srd_path2hashs_m
    // Because add this p_hash_u to the srd_path2hashs_m, so we cannot free p_hash_u
    sgx_thread_mutex_lock(&g_srd_mutex);
    wl->srd_path2hashs_m[path_str].push_back(p_hash_u);
    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    log_info("Seal random data -> %s, %luG success\n", hex_g_hash.c_str(), srd_total_num);
    sgx_thread_mutex_unlock(&g_srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(path_str, 1);
}

size_t srd_decrease_test(long change, std::map<std::string, std::set<size_t>> *srd_del_index_m)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    Workload *wl = Workload::get_instance();
    uint32_t change_num = 0;
    uint32_t srd_total_num = 0;
    uint32_t srd_del_num = 0;

    // Set delete set
    std::map<std::string, std::set<size_t>> tmp_m;
    if (srd_del_index_m == NULL)
    {
        srd_del_index_m = &tmp_m;
    }
    for (auto it : (*srd_del_index_m))
    {
        srd_del_num += it.second.size();
    }
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    change = std::min(change, (long)srd_total_num);
    if (change == 0)
    {
        return 0;
    }

    // Choose to be deleted g_hash index
    std::map<std::string, std::vector<uint8_t*>>::iterator chose_entry;
    size_t sAcc = 1;
    bool end_of_traverse = false;
    while (srd_del_num < change && !end_of_traverse)
    {
        end_of_traverse = true;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++)
        {
            if (it->second.size() >= sAcc)
            {
                size_t tIdx = it->second.size() - sAcc;
                if ((*srd_del_index_m)[it->first].find(tIdx) == (*srd_del_index_m)[it->first].end())
                {
                    (*srd_del_index_m)[it->first].insert(tIdx);
                    srd_del_num++;
                }
                end_of_traverse = false;
            }
        }
        sAcc++;
    }

    // Delete chose hashs in srd_path2hashs_m
    std::map<std::string, std::vector<std::string>> del_path2hashs_m;
    for (auto it : (*srd_del_index_m))
    {
        for (auto rit = it.second.rbegin(); rit != it.second.rend(); rit++)
        {
            std::vector<uint8_t*> *p_entry = &wl->srd_path2hashs_m[it.first];
            if ((*p_entry)[*rit] != NULL)
            {
                del_path2hashs_m[it.first].push_back(hexstring_safe((*p_entry)[*rit], HASH_LENGTH));
                free((*p_entry)[*rit]);
            }
            p_entry->erase(p_entry->begin() + *rit);
        }
    }

    // ----- Delete corresponding items ----- //
    // Do delete
    for (auto path_2_hash : del_path2hashs_m)
    {
        std::string del_dir = path_2_hash.first;
        for (auto del_hash : path_2_hash.second)
        {
            // --- Delete srd file --- //
            std::string del_path = path_2_hash.first + "/" + del_hash;
            //ocall_delete_folder_or_file(&crust_status, del_path.c_str());
            if (CRUST_SUCCESS != crust_status)
            {
                log_warn("Delete path:%s failed! Error code:%lx\n", del_path.c_str(), crust_status);
            }
            else
            {
                change_num++;
            }
        }
        // Reduce assigned space in srd info
        wl->set_srd_info(del_dir, -(long)(path_2_hash.second.size()));
    }

    return change_num;
}
EOF

    #local spos=$(sed -n '/void srd_increase(/=' $enclave_srd_cpp)
    #((spos += 2))
    #local epos=$(sed -n "$spos,$ {/^\}/=}" $enclave_srd_cpp | head -n 1)
    #((epos--))
    #sed -i "$spos,$epos d" $enclave_srd_cpp
    #sed -i "$((spos -= 1)) r $TMPFILE" $enclave_srd_cpp

    #sed -i "s/ocall_delete_folder_or_file(/\/\/ocall_delete_folder_or_file(/g" $enclave_srd_cpp
}

########## enc_wl_h_test ##########
function enc_wl_h_test()
{
cat << EOF > $TMPFILE

    void test_add_file(long file_num);
    void test_valid_file(uint32_t file_num);
    void test_lost_file(uint32_t file_num);
    void test_delete_file(uint32_t file_num);
    void test_delete_file_unsafe(uint32_t file_num);
EOF

    local spos=$(sed -n '/handle_report_result(/=' $enclave_workload_h)
    ((spos++))
    sed -i "$spos r $TMPFILE" $enclave_workload_h
}

########## enc_wl_cpp_test ##########
function enc_wl_cpp_test()
{
cat << EOF >> $enclave_workload_cpp

void Workload::test_add_file(long file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    long acc = 0;
    for (long i = 0; i < file_num; i++)
    {
        uint8_t *n_u = new uint8_t[32];
        sgx_read_rand(n_u, HASH_LENGTH);
        sgx_sha256_hash_t hash;
        sgx_sha256_hash_t old_hash;
        sgx_sha256_msg(n_u, HASH_LENGTH, &hash);
        sgx_sha256_msg(reinterpret_cast<uint8_t *>(&hash), HASH_LENGTH, &old_hash);
        json::JSON file_entry_json;
        file_entry_json[FILE_HASH] = reinterpret_cast<uint8_t *>(hash);
        file_entry_json[FILE_OLD_HASH] = reinterpret_cast<uint8_t *>(old_hash);
        file_entry_json[FILE_SIZE] = 10000;
        file_entry_json[FILE_OLD_SIZE] = 9999;
        file_entry_json[FILE_BLOCK_NUM] = 1000;
        // Status indicates current new file's status, which must be one of valid, lost and unconfirmed
        file_entry_json[FILE_STATUS] = "000";
        free(n_u);
        this->checked_files.push_back(file_entry_json);
        this->set_wl_spec(FILE_STATUS_UNCONFIRMED, file_entry_json[FILE_OLD_SIZE].ToInt());
        acc++;
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

void Workload::test_valid_file(uint32_t file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    for (uint32_t i = 0, j = 0; i < this->checked_files.size() && j < file_num; i++)
    {
        auto status = &this->checked_files[i][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_UNCONFIRMED
                || status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST)
        {
            this->set_wl_spec(FILE_STATUS_VALID, status->get_char(CURRENT_STATUS), this->checked_files[i][FILE_OLD_SIZE].ToInt());
            status->set_char(CURRENT_STATUS, FILE_STATUS_VALID);
            j++;
        }
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

void Workload::test_lost_file(uint32_t file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    if (this->checked_files.size() == 0)
    {
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
        return;
    }
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % this->checked_files.size();
        auto status = &this->checked_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            this->set_wl_spec(FILE_STATUS_LOST, status->get_char(CURRENT_STATUS), this->checked_files[index][FILE_OLD_SIZE].ToInt());
            status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
            this->set_wl_spec(FILE_STATUS_LOST, status->get_char(CURRENT_STATUS), this->checked_files[index][FILE_OLD_SIZE].ToInt());
            i++;
            j = 0;
        }
        else
        {
            j++;
        }
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

void Workload::test_delete_file(uint32_t file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    if (this->checked_files.size() == 0)
    {
        sgx_thread_mutex_unlock(&g_checked_files_mutex);
        return;
    }
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % this->checked_files.size();
        auto status = &this->checked_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) != FILE_STATUS_DELETED)
        {
            this->set_wl_spec(status->get_char(CURRENT_STATUS), -this->checked_files[index][FILE_OLD_SIZE].ToInt());
            status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
            i++;
            j = 0;
        }
        else
        {
            j++;
        }
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

void Workload::test_delete_file_unsafe(uint32_t file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    file_num = std::min(this->checked_files.size(), (size_t)file_num);
    this->checked_files.erase(this->checked_files.begin(), this->checked_files.begin() + file_num);
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}
EOF

    local spos=$(sed -n "/this->report_has_validated_proof(/=" $enclave_workload_cpp)
    sed -i "$spos, $((spos+4)) d" $enclave_workload_cpp
}

########## enc_id_cpp_test ##########
function enc_id_cpp_test()
{
cat << EOF >$TMPFILE
    json::JSON gened_wr_json;
    std::string gened_srd_root;
    uint8_t *p_gened_srd_root = NULL;

EOF
    local pos=$(sed -n '/size_t random_time = 0;/=' $enclave_identity_cpp)
    sed -i "$pos r $TMPFILE" $enclave_identity_cpp

cat << EOF >$TMPFILE
    // Check root
    gened_wr_json = json::JSON::Load(get_generated_work_report());
    gened_srd_root = gened_wr_json[WORKREPORT_RESERVED_ROOT].ToString();
    p_gened_srd_root = hex_string_to_bytes(gened_srd_root.c_str(), gened_srd_root.size());
    if (memcmp(p_gened_srd_root, wl_info[WL_SRD_ROOT_HASH].ToBytes(), HASH_LENGTH) != 0)
    {
        crust_status = CRUST_UNEXPECTED_ERROR;
        goto cleanup;
    }
EOF
    pos=$(sed -n '/crust_status = wl->serialize_file(/=' $enclave_identity_cpp)
    sed -i "$((pos+5)) r $TMPFILE" $enclave_identity_cpp

    pos=$(sed -n '/ocall_get_block_hash(/=' $enclave_identity_cpp)
    sed -i "$pos a \\\tsgx_read_rand(reinterpret_cast<uint8_t *>(report_hash), HASH_LENGTH);" $enclave_identity_cpp
    sed -i "$((pos+1)) a \\\tmemcpy(report_hash, hexstring_safe(report_hash, HASH_LENGTH).c_str(), HASH_LENGTH * 2);" $enclave_identity_cpp
    sed -i "$pos d" $enclave_identity_cpp
}

########## enc_storage_cpp_test ##########
function enc_storage_cpp_test()
{
    sed -i "s/ocall_replace_file(/\/\/ocall_replace_file(/g" $enclave_storage_cpp
}

########## enc_parameter_h_test ##########
function enc_parameter_h_test()
{
    sed -i "/#define WORKREPORT_FILE_LIMIT 1000/ c #define WORKREPORT_FILE_LIMIT 6" $enclave_parameter_h
}

########## ocalls_cpp_test ##########
function ocalls_cpp_test()
{
cat << EOF >> $ocalls_cpp

crust_status_t ocall_get_file_bench(const char */*file_path*/, unsigned char **p_file, size_t *len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (access("<%CRUST_TEST_SRD_PATH%>", 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat ("<%CRUST_TEST_SRD_PATH%>", &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open("<%CRUST_TEST_SRD_PATH%>", std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    if (*len > ocall_file_data_len)
    {
        ocall_file_data_len = 1024 * (*len / 1024) + ((*len % 1024) ? 1024 : 0);
        ocall_file_data = (uint8_t*)realloc(ocall_file_data, ocall_file_data_len);
        if (ocall_file_data == NULL)
        {
            in.close();
            return CRUST_MALLOC_FAILED;
        }
    }

    in.read(reinterpret_cast<char *>(ocall_file_data), *len);
    in.close();

    *p_file = ocall_file_data;

    return crust_status;
}

void ocall_store_file_info(const char *info)
{
    EnclaveData::get_instance()->set_file_info(info);
}

crust_status_t ocall_get_file_block(const char *file_path, unsigned char **p_file, size_t *len)
{
    std::string file_path_r = std::string("<%CRUST_FILE_PATH%>").append(file_path);
    if (access(file_path_r.c_str(), 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat (file_path_r.c_str(), &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(file_path_r, std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    if (*len > ocall_file_data_len)
    {
        ocall_file_data_len = 1024 * (*len / 1024) + ((*len % 1024) ? 1024 : 0);
        ocall_file_data = (uint8_t*)realloc(ocall_file_data, ocall_file_data_len);
        if (ocall_file_data == NULL)
        {
            in.close();
            return CRUST_MALLOC_FAILED;
        }
    }

    in.read(reinterpret_cast<char *>(ocall_file_data), *len);
    in.close();

    *p_file = ocall_file_data;

    return CRUST_SUCCESS;
}
EOF

cat << EOF > $TMPFILE
    std::string leaf_hash_str(leaf_hash);
    size_t spos = leaf_hash_str.find("_");
    if (spos == leaf_hash_str.npos)
    {
        p_log->err("Invalid merkletree leaf hash!\n");
        return CRUST_INVALID_MERKLETREE;
    }
    std::string leaf_hash_r = leaf_hash_str.substr(spos + 1, leaf_hash_str.size());

    std::string file_path = CRUST_INST_DIR;
    file_path.append("/files/").append(root_hash).append("/").append(leaf_hash_str);

    // Get file block data
    std::ifstream in;
    in.open(file_path, std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }
    in.seekg(0, std::ios::end);
    size_t len = in.tellg();
    in.seekg(0, std::ios::beg);
    if (len > _validate_data_size)
    {
        _validate_data_size = 1024 * (len / 1024) + ((len % 1024) ? 1024 : 0);
        _validate_data_buf = (uint8_t*)realloc(_validate_data_buf, _validate_data_size);
        if (_validate_data_buf == NULL)
        {
            return CRUST_MALLOC_FAILED;
        }
    }
    in.read(reinterpret_cast<char *>(_validate_data_buf), len);
    in.close();
    *p_sealed_data = _validate_data_buf;
    *sealed_data_size = len;

    return CRUST_SUCCESS;
EOF

    local spos=$(sed -n '/size_t _sealed_data_size = 0;/=' $ocalls_cpp)
    sed -i -e "$spos a uint8_t *_validate_data_buf = NULL;" \
        -e "$((spos++)) a size_t _validate_data_size = 0;" $ocalls_cpp

    spos=$(sed -n '/ocall_validate_get_file(/=' $ocalls_cpp)
    ((spos+=3))
    local epos=$(sed -n "$spos,$ {/^\}/=}" $ocalls_cpp | head -n 1)
    sed -i "$spos,$((epos-1)) d" $ocalls_cpp
    sed -i "$((spos-=1)) r $TMPFILE" $ocalls_cpp

    spos=$(sed -n '/p_log->info("Sending work report:/=' $ocalls_cpp)
    sed -i "$((spos+1)),$((spos+8)) d" $ocalls_cpp

    sed -i "/p_log->info(\"Sending work report/ a \\\tEnclaveData::get_instance()->set_enclave_workreport(work_str);" $ocalls_cpp

    spos=$(sed -n '/\/\/ Send identity to crust chain/=' $ocalls_cpp)
    sed -i "$spos,$((spos+9)) d" $ocalls_cpp
}

########## ocalls_h_test ##########
function ocalls_h_test()
{
    sed -i '/ocall_store_upgrade_data(/a void ocall_store_file_info(const char *info);' $ocalls_h
    sed -i '/ocall_store_upgrade_data(/a crust_status_t ocall_get_file_bench(const char *file_path, unsigned char **p_file, size_t *len);' $ocalls_h
    sed -i '/ocall_store_upgrade_data(/a crust_status_t ocall_get_file_block(const char *file_path, unsigned char **p_file, size_t *len);' $ocalls_h
}

function InstallAPP()
{
    mkdir -p $testdir
    mkdir -p $testdir/bin
    mkdir -p $testdir/etc
    mkdir -p $testdir/files
    sed -i "s@<%CRUST_FILE_PATH%>@$testdir/files/@g" $ocalls_cpp
    sed -i "s@<%CRUST_TEST_SRD_PATH%>@$srdtestfilepath@g" $ocalls_cpp

    cd $srcdir
    make clean && make -j8
    if [ $? -ne 0 ]; then
        echo "[ERROR] Make failed!"
        exit 1
    fi
    cd - &>/dev/null
    mv $srcdir/crust-sworker $testdir/bin
    mv $srcdir/enclave.signed.so $testdir/etc
    cp $srcdir/Config.json $testdir/etc
    cp $basedir/VERSION $testdir

    # Modify config file
    sed -i -e "/\"base_path\" :/c \\\t\"base_path\" : \"$testdir/sworker_base_path\"," \
        -e "/\"srd_paths\" :/c \\\t\"srd_paths\" : [\"$testdir/sworker_base_path/srd\"]," $configfile
    sed -i "s/<VERSION>\///g" $configfile
}

function success_exit()
{
    rm -rf $TMPFILE
    rm -rf $TMPFILE2
}

############### MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$basedir
devrootdir=$(cd $basedir/../..;pwd)
scriptdir=$basedir/scripts
datadir=$instdir/data
srdtestfilepath=$datadir/srd_test
srcdir=$basedir/src
appdir=$srcdir/app
encdir=$srcdir/enclave
enclave_cpp=$encdir/Enclave.cpp
enclave_edl=$encdir/Enclave.edl
ecalls_cpp=$appdir/ecalls/ECalls.cpp
ecalls_h=$appdir/ecalls/ECalls.h
process_cpp=$appdir/process/Process.cpp
storage_cpp=$appdir/process/Storage.cpp
storage_h=$appdir/process/Storage.h
resource_h=$appdir/include/Resource.h
apihandler_h=$appdir/http/ApiHandler.h
webserver_cpp=$appdir/http/WebServer.cpp
data_cpp=$appdir/process/EnclaveData.cpp
data_h=$appdir/process/EnclaveData.h
srd_cpp=$appdir/process/Srd.cpp
srd_h=$appdir/process/Srd.h
ocalls_cpp=$appdir/ocalls/OCalls.cpp
ocalls_h=$appdir/ocalls/OCalls.h
enclave_report_cpp=$encdir/report/Report.cpp
enclave_validate_cpp=$encdir/validator/Validator.cpp
enclave_validate_h=$encdir/validator/Validator.h
enclave_srd_cpp=$encdir/srd/Srd.cpp
enclave_srd_h=$encdir/srd/Srd.h
enclave_storage_cpp=$encdir/storage/Storage.cpp
enclave_parameter_h=$encdir/include/Parameter.h
enclave_workload_cpp=$encdir/workload/Workload.cpp
enclave_workload_h=$encdir/workload/Workload.h
enclave_identity_cpp=$encdir/identity/Identity.cpp
testdir=$basedir/test_app
configfile=$testdir/etc/Config.json
TMPFILE=$basedir/tmp.$$
TMPFILE2=$basedir/tmp2.$$

trap "success_exit" EXIT

. $scriptdir/utils.sh

rm -rf $basedir/src
rm -rf $testdir
cp -r $devrootdir/src ./
cp -r $devrootdir/buildenv.mk ./

# Check if jq is installed
if ! dpkg -l | grep "\bjq\b" &>/dev/null; then
    verbose WARN "jq is required!"
    sudo apt-get install -y jq
    if [ $? -ne 0 ]; then
        verbose ERROR "Install jq failed!"
        exit 1
    fi
    verbose INFO "Install jq successfully!"
fi

resource_h_test
ecalls_cpp_test
ecalls_h_test
process_cpp_test
storage_cpp_test
storage_h_test
apihandler_h_test
webserver_cpp_test
enclavedata_cpp_test
enclavedata_h_test
srd_cpp_test
srd_h_test
ocalls_cpp_test
ocalls_h_test
enclave_cpp_test
enclave_edl_test
enc_report_cpp_test
enc_validate_cpp_test
enc_validate_h_test
enc_srd_cpp_test
enc_srd_h_test
enc_wl_cpp_test
enc_wl_h_test
enc_id_cpp_test
#enc_parameter_h_test
#enc_storage_cpp_test

InstallAPP
