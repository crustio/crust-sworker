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
    validate_srd();
}

void ecall_validate_srd_real()
{
    validate_srd_real();
}

void ecall_validate_file()
{
    validate_meaningful_file();
}

void ecall_validate_file_real()
{
    validate_meaningful_file_real();
}

void ecall_validate_file_bench()
{
    validate_meaningful_file_bench();
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

    srd_increase_test(path);
}

size_t ecall_srd_decrease_test(long change)
{
    size_t ret = srd_decrease_test(change);

    return ret;
}

void ecall_clean_file()
{
    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&wl->file_mutex);
    wl->sealed_files.clear();
    sgx_thread_mutex_unlock(&wl->file_mutex);
}

crust_status_t ecall_get_file_info(const char *data)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    crust_status_t crust_status = CRUST_UNEXPECTED_ERROR;
    for (int i = wl->sealed_files.size() - 1; i >= 0; i--)
    {
        if (wl->sealed_files[i][FILE_HASH].ToString().compare(data) == 0)
        {
            std::string file_info_str = wl->sealed_files[i].dump();
            remove_char(file_info_str, '\n');
            remove_char(file_info_str, '\\\\');
            remove_char(file_info_str, ' ');
            ocall_store_file_info_test(file_info_str.c_str());
            crust_status = CRUST_SUCCESS;
        }
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    return crust_status;
}
EOF
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
        public void ecall_test_delete_file(uint32_t file_num);
        public void ecall_test_delete_file_unsafe(uint32_t file_num);
        public void ecall_clean_file();

        public crust_status_t ecall_get_file_info([in, string] const char *data);
EOF
    
    local pos=$(sed -n '/ecall_get_workload()/=' $enclave_edl)
    sed -i "$pos r $TMPFILE" $enclave_edl
    if [ $? -ne 0 ]; then
        echo "Replace enclave_edl_test failed!"
        exit 1
    fi

    sed -i "/void ocall_store_upgrade_data(/a \\\t\\tvoid ocall_store_file_info_test([in, string] const char *info);" $enclave_edl
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
	{"Ecall_test_delete_file", 1},
	{"Ecall_test_delete_file_unsafe", 1},
	{"Ecall_clean_file", 1},
	{"Ecall_get_file_info", 3},
    {"Ecall_srd_decrease_test", 1},
    {"Ecall_srd_increase_test", 2},
EOF
    local pos=$(sed -n '/{"Ecall_delete_file", 0},/=' $ecalls_cpp)
    sed -i "$pos r $TMPFILE" $ecalls_cpp
    if [ $? -ne 0 ]; then
        echo "Replace ecalls_cpp_test failed!"
        exit 1
    fi

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
sgx_status_t Ecall_test_delete_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_delete_file_unsafe(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_clean_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_get_file_info(sgx_enclave_id_t eid, crust_status_t *status, const char *data);
EOF

    local pos=$(sed -n '/sgx_status_t Ecall_get_workload(sgx_enclave_id_t eid);/=' $ecalls_h)
    sed -i "$((pos+1)) r $TMPFILE" $ecalls_h
    if [ $? -ne 0 ]; then
        echo "Replace ecalls_h_test failed!"
        exit 1
    fi
}

########## process_cpp_test ##########
function process_cpp_test()
{
    local pos1=$(sed -n '/&work_report_loop/=' $process_cpp)
    sed -i "$((pos1-1)),$pos1 d" $process_cpp
    if [ $? -ne 0 ]; then
        echo "Replace work_report_loop failed!"
        exit 1
    fi

    local pos2=$(sed -n '/&srd_check_reserved/=' $process_cpp)
    sed -i "$((pos2-1)),$pos2 d" $process_cpp
    if [ $? -ne 0 ]; then
        echo "Replace srd_check_reserved failed!"
        exit 1
    fi

    local pos3=$(sed -n '/&main_loop/=' $process_cpp)
    sed -i "$((pos3-1)),$pos3 d" $process_cpp
    if [ $? -ne 0 ]; then
        echo "Replace main_loop failed!"
        exit 1
    fi

    # Get block to gen upgrade data
    local pos4=$(sed -n '/crust::BlockHeader/=' $process_cpp)
    local arry=($pos4)
    if [ ${#arry[@]} -ne 1 ]; then
        echo "Replace blockheader failed!"
        exit 1
    fi
    sed -i "$pos4,$((pos4+5)) d" $process_cpp
    sed -i "$((pos4-1)) a \\\t\t\tif (SGX_SUCCESS != (sgx_status = Ecall_gen_upgrade_data(global_eid, &crust_status, g_block_height+REPORT_BLOCK_HEIGHT_BASE+REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT)))" $process_cpp
    sed -i "/extern bool g_upgrade_flag;/ a extern size_t g_block_height;" $process_cpp
    pos4=$(sed -n '/if (UPGRADE_STATUS_EXIT == ed->get_upgrade_status(/=' $process_cpp)
    sed -i "$((pos4+1)) a \\\t\t\tg_block_height += REPORT_BLOCK_HEIGHT_BASE;" $process_cpp
    if [ $? -ne 0 ]; then
        echo "Replace get_upgrade_status failed!"
        exit 1
    fi
}

########## async_cpp_test ##########
function async_cpp_test()
{
cat << EOF >> $async_cpp

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

########## async_h_test ##########
function async_h_test()
{
    local spos=$(sed -n "/void async_storage_delete(/=" $async_h)
    sed -i "$spos a void report_add_callback();" $async_h
    if [ $? -ne 0 ]; then
        echo "Replace async_storage_delete failed!"
        exit 1
    fi
}

########## apihandler_h_test ##########
function apihandler_h_test()
{
cat << EOF > $TMPFILE

        cur_path = urlendpoint.base + "/report/work";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            crust_status_t crust_status = CRUST_SUCCESS;
            uint8_t *hash_u = (uint8_t *)malloc(32);
            int tmp_int;
            int ret_code = 400;
            std::string ret_info;
            json::JSON ret_body;
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
                res.result(400);
                ret_info = "Get signed work report failed!";
                p_log->err("%s\n", ret_info.c_str());
            }
            else
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    // Send signed validation report to crust chain
                    p_log->info("Send work report successfully!\n");
                    std::string work_str = ed->get_enclave_workreport();
                    res.body() = work_str;
                    res.result(200);
                    goto getcleanup;
                }
                if (crust_status == CRUST_BLOCK_HEIGHT_EXPIRED)
                {
                    ret_code = 401;
                    ret_info = "Block height expired.";
                    p_log->info("%s\n", ret_info.c_str());
                }
                else if (crust_status == CRUST_FIRST_WORK_REPORT_AFTER_REPORT)
                {
                    ret_code = 402;
                    ret_info = "Can't generate work report for the first time after restart";
                    p_log->info("%s\n", ret_info.c_str());
                }
                else
                {
                    ret_code = 403;
                    ret_info = "Get signed validation report failed!";
                    p_log->err("%s Error code: %x\n", ret_info.c_str(), crust_status);
                }
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();
            goto getcleanup;
        }

        // --- Srd change API --- //
        cur_path = urlendpoint.base + "/report/result";
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

        cur_path = urlendpoint.base + "/validate/srd";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_srd(global_eid);
        }

        cur_path = urlendpoint.base + "/validate/srd_real";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_srd_real(global_eid);
        }

        cur_path = urlendpoint.base + "/validate/file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_file(global_eid);
        }

        cur_path = urlendpoint.base + "/validate/file_real";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_file_real(global_eid);
        }

        cur_path = urlendpoint.base + "/validate/file_bench";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_validate_file_bench(global_eid);
        }

        cur_path = urlendpoint.base + "/store_metadata";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_store_metadata(global_eid);
        }

        cur_path = urlendpoint.base + "/test/add_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            long file_num = req_json["file_num"].ToInt();
            Ecall_test_add_file(global_eid, file_num);
            res.body() = "Add file successfully!";
        }

        cur_path = urlendpoint.base + "/test/delete_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_delete_file(global_eid, file_num);
            res.body() = "Delete file successfully!";
        }

        cur_path = urlendpoint.base + "/test/delete_file_unsafe";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_delete_file_unsafe(global_eid, file_num);
            res.body() = "Delete file successfully!";
        }

        cur_path = urlendpoint.base + "/clean_file";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            Ecall_clean_file(global_eid);
            res.body() = "Clean file successfully!";
        }

        cur_path = urlendpoint.base + "/file_info";
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

        cur_path = urlendpoint.base + "/storage/seal_sync";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            int ret_code = 400;
            json::JSON ret_body;

            p_log->info("Dealing with seal request...\n");

            // Parse paramters
            json::JSON req_json = json::JSON::Load(req.body());
            std::string cid = req_json["cid"].ToString();
            if (cid.size() != CID_LENGTH)
            {
                p_log->err("Invalid cid!\n");
                ret_body[HTTP_STATUS_CODE] = 400;
                ret_body[HTTP_MESSAGE] = "Invalid cid!";
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
                goto postcleanup;
            }

            // ----- Seal file ----- //
            sgx_status_t sgx_status = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            if (SGX_SUCCESS != (sgx_status = Ecall_seal_file(global_eid, &crust_status, cid.c_str())))
            {
                ret_code = 401;
                ret_info = "Sealing file failed!Invoke SGX API failed!";
                p_log->err("Seal file(%s) failed!Invoke SGX API failed!Error code:%lx\n", cid.c_str(), sgx_status);
            }
            else if (CRUST_SUCCESS != crust_status)
            {
                switch (crust_status)
                {
                case CRUST_SEAL_DATA_FAILED:
                    p_log->err("Seal file(%s) failed!Internal error: seal data failed!\n", cid.c_str());
                    break;
                case CRUST_FILE_NUMBER_EXCEED:
                    p_log->err("Seal file(%s) failed!No more file can be sealed!File number reachs the upper limit!\n", cid.c_str());
                    break;
                case CRUST_UPGRADE_IS_UPGRADING:
                    p_log->err("Seal file(%s) failed due to upgrade!\n", cid.c_str());
                    break;
                case CRUST_STORAGE_FILE_DUP:
                    p_log->err("Seal file(%s) failed!This file has been sealed.\n", cid.c_str());
                    break;
                default:
                    p_log->err("Seal file(%s) failed!Unexpected error!\n", cid.c_str());
                }
                ret_info = "Sealing file failed!";
                ret_code = 402;
            }
            else
            {
                ret_code = 200;
                ret_info = "Sealing file successfully!";
                p_log->info("Seal file(%s) successfully!\n", cid.c_str());
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();

            goto postcleanup;
        }

        cur_path = urlendpoint.base + "/storage/delete_sync";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            res.result(200);
            std::string ret_info;
            int ret_code = 400;
            json::JSON ret_body;
            // Delete file
            json::JSON req_json = json::JSON::Load(req.body());
            std::string cid = req_json["cid"].ToString();
            // Check cid
            if (cid.size() != CID_LENGTH)
            {
                ret_info = "Delete file failed!Invalid cid!";
                p_log->err("%s\n", ret_info.c_str());
                ret_code = 400;
                ret_body[HTTP_STATUS_CODE] = ret_code;
                ret_body[HTTP_MESSAGE] = ret_info;
                res.result(ret_body[HTTP_STATUS_CODE].ToInt());
                res.body() = ret_body.dump();
                goto postcleanup;
            }
            
            sgx_status_t sgx_status = SGX_SUCCESS;
            crust_status_t crust_status = CRUST_SUCCESS;
            ret_info = "Deleting file failed!";
            if (SGX_SUCCESS != (sgx_status = Ecall_delete_file(global_eid, &crust_status, cid.c_str())))
            {
                ret_code = 401;
                ret_info = "Delete file failed!";
                p_log->err("Delete file(%s) failed!Invoke SGX API failed!Error code:%lx\n", cid.c_str(), sgx_status);
            }
            else if (CRUST_SUCCESS != crust_status)
            {
                ret_code = 402;
                ret_info = "Delete file failed!";
                p_log->err("Delete file(%s) failed!Error code:%lx\n", cid.c_str(), crust_status);
            }
            else
            {
                EnclaveData::get_instance()->del_sealed_file_info(cid);
                p_log->info("Delete file(%s) successfully!\n", cid.c_str());
                res.result(200);
                res.body() = "Deleting file successfully!";
                goto postcleanup;
            }

            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();

            goto postcleanup;
        }

        cur_path = urlendpoint.base + "/srd/set_change";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            // Check input parameters
            json::JSON req_json = json::JSON::Load(req.body());
            change_srd_num = req_json["change"].ToInt();

            if (change_srd_num == 0)
            {
                p_log->info("Invalid change\n");
                ret_info = "Invalid change";
                ret_code = 400;
            }
            else
            {
                // Start changing srd
                crust_status_t crust_status = CRUST_SUCCESS;
                long real_change = 0;
                if (SGX_SUCCESS != Ecall_change_srd_task(global_eid, &crust_status, change_srd_num, &real_change))
                {
                    ret_info = "Change srd failed!Invoke SGX api failed!";
                    ret_code = 401;
                }
                else
                {
                    char buffer[256];
                    memset(buffer, 0, 256);
                    switch (crust_status)
                    {
                    case CRUST_SUCCESS:
                        sprintf(buffer, "Change task:%ldG has been added, will be executed later.\n", real_change);
                        ret_code = 200;
                        break;
                    case CRUST_SRD_NUMBER_EXCEED:
                        sprintf(buffer, "Only %ldG srd will be added.Rest srd task exceeds upper limit.\n", real_change);
                        ret_code = 402;
                        break;
                    default:
                        sprintf(buffer, "Unexpected error has occurred!\n");
                        ret_code = 403;
                    }
                    ret_info.append(buffer);
                }
                p_log->info("%s", ret_info.c_str());
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();
            goto postcleanup;
        }

        cur_path = urlendpoint.base + "/srd/change_real";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
            std::string ret_info;
            // Check input parameters
            json::JSON req_json = json::JSON::Load(req.body());
            change_srd_num = req_json["change"].ToInt();

            if (change_srd_num == 0)
            {
                p_log->info("Invalid change\n");
                ret_info = "Invalid change";
                ret_code = 400;
            }
            else
            {
                // Start changing srd
				srd_change(change_srd_num);
                ret_info = "Change srd successfully!";
                ret_code = 200;
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();
            goto postcleanup;
        }

        cur_path = urlendpoint.base + "/srd/change_disk";
        if (req_route.size() == cur_path.size() && req_route.compare(cur_path) == 0)
        {
            json::JSON ret_body;
            int ret_code = 400;
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
                ret_code = 400;
                ret_info = "Wrong paths structure!";
                p_log->err("%s\n", ret_info.c_str());
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
                    ret_code = 200;
                    ret_info = "Add srd path successfully!";
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
                    ret_code = 200;
                    ret_info = "Delete srd path successfully!";
                }
                else
                {
                    ret_code = 401;
                    ret_info = "Please indicate operation: add or delete!";
                    p_log->err("%s\n", ret_info.c_str());
                }
                p_log->info("paths:%s\n", p_config->srd_paths.dump().c_str());
            }
            ret_body[HTTP_STATUS_CODE] = ret_code;
            ret_body[HTTP_MESSAGE] = ret_info;
            res.result(ret_body[HTTP_STATUS_CODE].ToInt());
            res.body() = ret_body.dump();

            goto postcleanup;
        }
EOF

    # Add get signed workreport and signed order report API 
    local pos=$(sed -n '/getcleanup:/=' $apihandler_h)
    ((pos-=2))
    sed -i "$pos r $TMPFILE" $apihandler_h
    if [ $? -ne 0 ]; then
        echo "Replace apihandler_h 1 failed!"
        exit 1
    fi

    # Srd directly
    pos=$(sed -n '/Ecall_change_srd_task/=' $apihandler_h)
    sed -i "$((pos-2)),$((pos+24)) d " $apihandler_h
    if [ $? -ne 0 ]; then
        echo "Replace apihandler_h 2 failed!"
        exit 1
    fi
cat << EOF > $TMPFILE
				if (!srd_change_test(change_srd_num))
                {
                    ret_info = "Change srd failed!";
                    ret_code = 401;
                }
                else
                {
                    ret_info = "Change srd successfully!";
                    ret_code = 200;
                }
EOF
    sed -i "$((pos-2)) r $TMPFILE" $apihandler_h

    # Add POST APIs
    pos=$(sed -n '/srd_change_test(/=' $apihandler_h)
    ((pos+=16))
    sed -i "$pos r $TMPFILE2" $apihandler_h
    if [ $? -ne 0 ]; then
        echo "Replace apihandler_h 3 failed!"
        exit 1
    fi

    # Upgrade start
    pos=$(sed -n '/crust::BlockHeader block_header;/=' $apihandler_h)
    sed -i "$pos, $((pos+6)) d" $apihandler_h
    if [ $? -ne 0 ]; then
        echo "Replace apihandler_h 4 failed!"
        exit 1
    fi
    sed -i "/Ecall_enable_upgrade/ c \\\t\t\tif (SGX_SUCCESS != (sgx_status = Ecall_enable_upgrade(global_eid, &crust_status, g_block_height+REPORT_BLOCK_HEIGHT_BASE+REPORT_INTERVAL_BLCOK_NUMBER_LOWER_LIMIT)))" $apihandler_h

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
    sed -i "/size_t get_reserved_space();/ a bool srd_change_test(long change);" $srd_h
}

function srd_cpp_test()
{
cat << EOF >> $srd_cpp
bool srd_change_test(long change)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    crust_status_t crust_status = CRUST_SUCCESS;
    Config *p_config = Config::get_instance();
    bool res = true;

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
                res = false;
            }
            else
            {
                switch (crust_status)
                {
                case CRUST_SUCCESS:
                    p_log->info("Add left srd task successfully!%ldG has been added, will be executed later.\n", real_change);
                    break;
                case CRUST_SRD_NUMBER_EXCEED:
                    p_log->warn("Add left srd task failed!Srd number has reached the upper limit!Real srd task is %ldG.\n", real_change);
                    res = false;
                    break;
                default:
                    res = false;
                    p_log->info("Unexpected error has occurred!\n");
                }
            }
            //p_log->info("%ldG srd task left, add it to next srd.\n", left_srd_num);
        }
        if (true_increase == 0)
        {
            //p_log->warn("No available space for srd!\n");
            return res;
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

        p_log->info("Increase %dG srd files success\n", true_increase);
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
            return res;
        }
        p_log->info("True decreased space is:%d\n", true_decrease);
        Ecall_srd_decrease_test(global_eid, &ret_size, true_decrease);
        total_decrease_size = ret_size;
        p_log->info("Decrease %luG srd files success, the srd workload will change in next validation loop\n", total_decrease_size);
    }

    return res;
}
EOF
}

########## enc_report_cpp_test ##########
function enc_report_cpp_test()
{
    local spos=$(sed -n '/crust_status_t gen_work_report(/=' $enclave_report_cpp)
    sed -i "$((spos+15)),$((spos+19)) d" $enclave_report_cpp
    if [ $? -ne 0 ]; then
        echo "Replace enc_report_cpp_test failed!"
        exit 1
    fi

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
    ### Delete old validate srd func
    spos=$(sed -n '/void validate_srd()/=' $enclave_validate_cpp)
    epos=$(sed -n "$spos,$ {/^}/=}" $enclave_validate_cpp | head -n 1)
    sed -i "$spos,$epos d" $enclave_validate_cpp
    if [ $? -ne 0 ]; then
        echo "Replace enc_validate_cpp_test 3 failed!"
        exit 1
    fi

cat << EOF >>$enclave_validate_cpp

void validate_srd()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&wl->srd_mutex);

    size_t srd_total_num = 0;
    for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end();)
    {
        if (0 == it->second.size())
        {
            it = wl->srd_path2hashs_m.erase(it);
        }
        else
        {
            srd_total_num += it->second.size();
            it++;
        }
    }
    size_t srd_validate_num = std::max((size_t)(srd_total_num * SRD_VALIDATE_RATE), (size_t)SRD_VALIDATE_MIN_NUM);
    srd_validate_num = std::min(srd_validate_num, srd_total_num);
    
    // Randomly choose validate srd files
    std::unordered_map<std::string, std::set<std::pair<int, uint8_t *>>> validate_srd_idx_um;
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
            if (chose_entry == wl->srd_path2hashs_m.end())
            {
                break;
            }
            uint32_t path_idx = rand_val % wl->srd_path2hashs_m.size();
            for (uint32_t i = 0; i < path_idx; i++)
            {
                chose_entry++;
            }
            if (0 != chose_entry->second.size())
            {
                sgx_read_rand((uint8_t *)&rand_val, 4);
                rand_idx = rand_val % chose_entry->second.size();
                validate_srd_idx_um[chose_entry->first].insert(std::make_pair(rand_idx, chose_entry->second[rand_idx]));
            }
        }
    }
    else
    {
        int i = 0;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++, i++)
        {
            for (size_t j = 0; j < it->second.size(); j++)
            {
                validate_srd_idx_um[it->first].insert(std::make_pair(j, it->second[j]));
            }
        }
    }
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Validate SRD ----- //
    std::map<std::string, std::vector<uint8_t *>> del_path2hashs_m;
    for (auto path2srds : validate_srd_idx_um)
    {
        std::string dir_path = path2srds.first;
        for (auto idx_hash_item : path2srds.second)
        {
            std::string hex_g_hash;
            std::string g_path;

            uint8_t *p_g_hash = idx_hash_item.second;

            // Get g_hash corresponding path
            hex_g_hash = hexstring_safe(p_g_hash, HASH_LENGTH);
            g_path = std::string(dir_path).append("/").append(hexstring_safe(p_g_hash, HASH_LENGTH));

            // Get M hashs

            // Compare M hashs

            // Get leaf data

            // Compare leaf data

        }
    }

    // Delete failed srd metadata
    for (auto path2hashs : del_path2hashs_m)
    {
        std::string del_dir = path2hashs.first;
        for (auto g_hash : path2hashs.second)
        {
            std::string del_path = del_dir + "/" + hexstring_safe(g_hash, HASH_LENGTH);
            ocall_delete_folder_or_file(&crust_status, del_path.c_str());
        }
        // Reduce assigned space in srd info
        wl->set_srd_info(del_dir, -(long)(path2hashs.second.size()));
    }
}

void validate_srd_real()
{
    if (ENC_UPGRADE_STATUS_SUCCESS == Workload::get_instance()->get_upgrade_status())
    {
        return;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    Workload *wl = Workload::get_instance();

    sgx_thread_mutex_lock(&wl->srd_mutex);

    size_t srd_total_num = 0;
    for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end();)
    {
        if (0 == it->second.size())
        {
            it = wl->srd_path2hashs_m.erase(it);
        }
        else
        {
            srd_total_num += it->second.size();
            it++;
        }
    }
    size_t srd_validate_num = std::max((size_t)(srd_total_num * SRD_VALIDATE_RATE), (size_t)SRD_VALIDATE_MIN_NUM);
    srd_validate_num = std::min(srd_validate_num, srd_total_num);
    
    // Randomly choose validate srd files
    std::unordered_map<std::string, std::set<std::pair<int, uint8_t *>>> validate_srd_idx_um;
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
            if (chose_entry == wl->srd_path2hashs_m.end())
            {
                break;
            }
            uint32_t path_idx = rand_val % wl->srd_path2hashs_m.size();
            for (uint32_t i = 0; i < path_idx; i++)
            {
                chose_entry++;
            }
            if (0 != chose_entry->second.size())
            {
                sgx_read_rand((uint8_t *)&rand_val, 4);
                rand_idx = rand_val % chose_entry->second.size();
                validate_srd_idx_um[chose_entry->first].insert(std::make_pair(rand_idx, chose_entry->second[rand_idx]));
            }
        }
    }
    else
    {
        int i = 0;
        for (auto it = wl->srd_path2hashs_m.begin(); it != wl->srd_path2hashs_m.end(); it++, i++)
        {
            for (size_t j = 0; j < it->second.size(); j++)
            {
                validate_srd_idx_um[it->first].insert(std::make_pair(j, it->second[j]));
            }
        }
    }
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Validate SRD ----- //
    std::map<std::string, std::vector<uint8_t *>> del_path2hashs_m;
    for (auto path2srds : validate_srd_idx_um)
    {
        std::string dir_path = path2srds.first;
        for (auto idx_hash_item : path2srds.second)
        {
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
            std::string g_path;

            uint32_t g_hash_index = idx_hash_item.first;
            uint8_t *p_g_hash = idx_hash_item.second;

            // Get g_hash corresponding path
            hex_g_hash = hexstring_safe(p_g_hash, HASH_LENGTH);
            g_path = std::string(dir_path).append("/").append(hexstring_safe(p_g_hash, HASH_LENGTH));

            // Get M hashs
            ocall_get_file(&crust_status, get_m_hashs_file_path(g_path.c_str()).c_str(), &m_hashs_org, &m_hashs_size);
            if (m_hashs_org == NULL)
            {
                if (wl->is_srd_in_deleted_buffer(dir_path, g_hash_index))
                {
                    goto nextloop;
                }
                log_err("Get m hashs file(%s) failed.\n", g_path.c_str());
                del_path2hashs_m[dir_path].push_back(p_g_hash);
                wl->add_srd_to_deleted_buffer(dir_path, g_hash_index);
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
                log_err("Wrong m hashs file(%s).\n", g_path.c_str());
                del_path2hashs_m[dir_path].push_back(p_g_hash);
                wl->add_srd_to_deleted_buffer(dir_path, g_hash_index);
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
                if (wl->is_srd_in_deleted_buffer(dir_path, g_hash_index))
                {
                    goto nextloop;
                }
                log_err("Get leaf file(%s) failed.\n", g_path.c_str());
                del_path2hashs_m[dir_path].push_back(p_g_hash);
                wl->add_srd_to_deleted_buffer(dir_path, g_hash_index);
                goto nextloop;
            }

            // Compare leaf data
            sgx_sha256_msg(leaf_data, leaf_data_len, &leaf_hash);
            if (memcmp(m_hashs + srd_block_index * 32, leaf_hash, HASH_LENGTH) != 0)
            {
                log_err("Wrong leaf data hash '%s'(file path:%s).\n", hex_g_hash.c_str(), g_path.c_str());
                del_path2hashs_m[dir_path].push_back(p_g_hash);
                wl->add_srd_to_deleted_buffer(dir_path, g_hash_index);
                goto nextloop;
            }


        nextloop:
            if (m_hashs != NULL)
            {
                free(m_hashs);
            }
        }
    }

    // Delete failed srd metadata
    for (auto path2hashs : del_path2hashs_m)
    {
        std::string del_dir = path2hashs.first;
        for (auto g_hash : path2hashs.second)
        {
            std::string del_path = del_dir + "/" + hexstring_safe(g_hash, HASH_LENGTH);
            ocall_delete_folder_or_file(&crust_status, del_path.c_str());
        }
        // Reduce assigned space in srd info
        wl->set_srd_info(del_dir, -(long)(path2hashs.second.size()));
    }
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

    // Lock wl->sealed_files
    sgx_thread_mutex_lock(&wl->file_mutex);
    // Get to be checked files indexes
    size_t check_file_num = std::max((size_t)(wl->sealed_files.size() * MEANINGFUL_VALIDATE_RATE), (size_t)MEANINGFUL_VALIDATE_MIN_NUM);
    check_file_num = std::min(check_file_num, wl->sealed_files.size());
    std::map<uint32_t, json::JSON> validate_sealed_files_m;
    uint32_t rand_val;
    size_t rand_index = 0;
    for (size_t i = 0; i < check_file_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        rand_index = rand_val % wl->sealed_files.size();
        validate_sealed_files_m[rand_index] = wl->sealed_files[rand_index];
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    // ----- Validate file ----- //
    // Used to indicate which meaningful file status has been changed
    std::unordered_set<size_t> deleted_index_us;
    for (auto idx2file : validate_sealed_files_m)
    {
        // If new file hasn't been verified, skip this validation
        uint32_t file_idx = idx2file.first;
        json::JSON file = idx2file.second;
        auto status = file[FILE_STATUS];
        if (status.get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
        {
            continue;
        }

        std::string root_cid = file[FILE_CID].ToString();
        std::string root_hash = file[FILE_HASH].ToString();
        size_t file_block_num = file[FILE_BLOCK_NUM].ToInt();
        // Get tree string
        crust_status = persist_get_unsafe(root_cid, &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status)
        {
            if (wl->is_in_deleted_file_buffer(file_idx))
            {
                continue;
            }
            log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_cid.c_str());
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                deleted_index_us.insert(file_idx);
            }
            if (p_data != NULL)
            {
                free(p_data);
                p_data = NULL;
            }
            continue;
        }
        // Validate merkle tree
        std::string tree_str(reinterpret_cast<const char *>(p_data), data_len);
        if (p_data != NULL)
        {
            free(p_data);
            p_data = NULL;
        }
        json::JSON tree_json = json::JSON::Load(tree_str);
        bool valid_tree = true;
        if (root_hash.compare(tree_json[MT_HASH].ToString()) != 0)
        {
            log_err("File:%s merkle tree is not valid!Root hash doesn't equal!\n", root_cid.c_str());
            valid_tree = false;
        }
        if (CRUST_SUCCESS != (crust_status = validate_merkletree_json(tree_json)))
        {
            log_err("File:%s merkle tree is not valid!Invalid merkle tree,error code:%lx\n", root_cid.c_str(), crust_status);
            valid_tree = false;
        }
        if (!valid_tree)
        {
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                deleted_index_us.insert(file_idx);
            }
            continue;
        }

        // ----- Validate MerkleTree ----- //
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
        // Note: should store serialized tree structure as "cid":x,"hash":"xxxxx"
        // be careful to keep "cid", "hash" sequence
        size_t spos, epos;
        spos = epos = 0;
        std::string dcid_tag(MT_DATA_CID "\":\"");
        std::string dhash_tag(MT_DATA_HASH "\":\"");
        size_t cur_block_idx = 0;
        for (auto check_block_idx : block_idx_s)
        {
            // Get leaf node position
            do
            {
                spos = tree_str.find(dcid_tag, spos);
                if (spos == tree_str.npos)
                {
                    break;
                }
                spos += dcid_tag.size();
            } while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos)
            {
                log_err("Find file(%s) leaf node cid failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    deleted_index_us.insert(file_idx);
                }
                break;
            }
            // Get current node cid
            std::string cur_cid = tree_str.substr(spos, CID_LENGTH);
            // Get current node hash
            epos = tree_str.find(dhash_tag, spos);
            if (epos == tree_str.npos)
            {
                log_err("Find file(%s) leaf node hash failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    deleted_index_us.insert(file_idx);
                }
                break;
            }
            epos += dhash_tag.size();
            std::string leaf_hash = tree_str.substr(epos, HASH_LENGTH * 2);
            // Compute current node hash by data
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            crust_status = storage_ipfs_cat(cur_cid.c_str(), &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                if (p_sealed_data != NULL)
                {
                    free(p_sealed_data);
                }
                if (CRUST_SERVICE_UNAVAILABLE == crust_status)
                {
                    log_err("IPFS is offline!Please start it!\n");
                    wl->set_report_file_flag(false);
                    return;
                }
                if (wl->is_in_deleted_file_buffer(file_idx))
                {
                    continue;
                }
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    deleted_index_us.insert(file_idx);
                }
                log_err("Get file(%s) block:%ld failed!\n", root_cid.c_str(), check_block_idx);
                break;
            }
            // Validate hash
            sgx_sha256_hash_t got_hash;
            sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
            if (p_sealed_data != NULL)
            {
                free(p_sealed_data);
            }
            uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
            if (leaf_hash_u == NULL)
            {
                log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
                continue;
            }
            if (memcmp(leaf_hash_u, got_hash, HASH_LENGTH) != 0)
            {
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    log_err("File(%s) Index:%ld block hash is not expected!\n", root_cid.c_str(), check_block_idx);
                    log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                    log_err("Org hash : %s\n", leaf_hash.c_str());
                    deleted_index_us.insert(file_idx);
                }
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
    }

    // Change file status
    if (deleted_index_us.size() > 0)
    {
        sgx_thread_mutex_lock(&wl->file_mutex);
        for (auto index : deleted_index_us)
        {
            log_info("File status changed, hash: %s status: valid -> lost, will be deleted\n",
                    validate_sealed_files_m[index][FILE_CID].ToString().c_str());
            std::string cid = validate_sealed_files_m[index][FILE_CID].ToString();
            // Change file status
            if (validate_sealed_files_m[index][FILE_CHAIN_BLOCK_NUM].ToInt() >= wl->sealed_files[index][FILE_CHAIN_BLOCK_NUM].ToInt())
            {
                wl->sealed_files[index][FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                // Delete real file
                ocall_ipfs_del_all(&crust_status, cid.c_str());
                // Delete file tree structure
                persist_del(cid);
                // Reduce valid file
                wl->set_wl_spec(FILE_STATUS_VALID, -validate_sealed_files_m[index][FILE_SIZE].ToInt());
            }
        }
        sgx_thread_mutex_unlock(&wl->file_mutex);
    }
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

    // Lock wl->sealed_files
    sgx_thread_mutex_lock(&wl->file_mutex);
    // Get to be checked files indexes
    size_t check_file_num = std::max((size_t)(wl->sealed_files.size() * MEANINGFUL_VALIDATE_RATE), (size_t)MEANINGFUL_VALIDATE_MIN_NUM);
    check_file_num = std::min(check_file_num, wl->sealed_files.size());
    std::map<uint32_t, json::JSON> validate_sealed_files_m;
    uint32_t rand_val;
    size_t rand_index = 0;
    for (size_t i = 0; i < check_file_num; i++)
    {
        sgx_read_rand((uint8_t *)&rand_val, 4);
        rand_index = rand_val % wl->sealed_files.size();
        validate_sealed_files_m[rand_index] = wl->sealed_files[rand_index];
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);

    // ----- Validate file ----- //
    // Used to indicate which meaningful file status has been changed
    std::unordered_set<size_t> deleted_index_us;
    for (auto idx2file : validate_sealed_files_m)
    {
        // If new file hasn't been verified, skip this validation
        uint32_t file_idx = idx2file.first;
        json::JSON file = idx2file.second;
        auto status = file[FILE_STATUS];
        if (status.get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
        {
            continue;
        }

        std::string root_cid = file[FILE_CID].ToString();
        std::string root_hash = file[FILE_HASH].ToString();
        size_t file_block_num = file[FILE_BLOCK_NUM].ToInt();
        // Get tree string
        crust_status = persist_get_unsafe(root_cid, &p_data, &data_len);
        if (CRUST_SUCCESS != crust_status)
        {
            if (wl->is_in_deleted_file_buffer(file_idx))
            {
                continue;
            }
            log_err("Validate meaningful data failed! Get tree:%s failed!\n", root_cid.c_str());
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                deleted_index_us.insert(file_idx);
            }
            if (p_data != NULL)
            {
                free(p_data);
                p_data = NULL;
            }
            continue;
        }
        // Validate merkle tree
        std::string tree_str(reinterpret_cast<const char *>(p_data), data_len);
        if (p_data != NULL)
        {
            free(p_data);
            p_data = NULL;
        }
        json::JSON tree_json = json::JSON::Load(tree_str);
        bool valid_tree = true;
        if (root_hash.compare(tree_json[MT_HASH].ToString()) != 0)
        {
            log_err("File:%s merkle tree is not valid!Root hash doesn't equal!\n", root_cid.c_str());
            valid_tree = false;
        }
        if (CRUST_SUCCESS != (crust_status = validate_merkletree_json(tree_json)))
        {
            log_err("File:%s merkle tree is not valid!Invalid merkle tree,error code:%lx\n", root_cid.c_str(), crust_status);
            valid_tree = false;
        }
        if (!valid_tree)
        {
            if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
            {
                deleted_index_us.insert(file_idx);
            }
            continue;
        }

        // ----- Validate MerkleTree ----- //
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
        // Note: should store serialized tree structure as "cid":x,"hash":"xxxxx"
        // be careful to keep "cid", "hash" sequence
        size_t spos, epos;
        spos = epos = 0;
        std::string dcid_tag(MT_DATA_CID "\":\"");
        std::string dhash_tag(MT_DATA_HASH "\":\"");
        size_t cur_block_idx = 0;
        for (auto check_block_idx : block_idx_s)
        {
            // Get leaf node position
            do
            {
                spos = tree_str.find(dcid_tag, spos);
                if (spos == tree_str.npos)
                {
                    break;
                }
                spos += dcid_tag.size();
            } while (cur_block_idx++ < check_block_idx);
            if (spos == tree_str.npos)
            {
                log_err("Find file(%s) leaf node cid failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    deleted_index_us.insert(file_idx);
                }
                break;
            }
            // Get current node cid
            std::string cur_cid = tree_str.substr(spos, CID_LENGTH);
            // Get current node hash
            epos = tree_str.find(dhash_tag, spos);
            if (epos == tree_str.npos)
            {
                log_err("Find file(%s) leaf node hash failed!node index:%ld\n", root_cid.c_str(), check_block_idx);
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    deleted_index_us.insert(file_idx);
                }
                break;
            }
            epos += dhash_tag.size();
            std::string leaf_hash = tree_str.substr(epos, HASH_LENGTH * 2);
            // Compute current node hash by data
            uint8_t *p_sealed_data = NULL;
            size_t sealed_data_size = 0;
            crust_status = storage_ipfs_cat(cur_cid.c_str(), &p_sealed_data, &sealed_data_size);
            if (CRUST_SUCCESS != crust_status)
            {
                if (p_sealed_data != NULL)
                {
                    free(p_sealed_data);
                }
                if (CRUST_SERVICE_UNAVAILABLE == crust_status)
                {
                    log_err("IPFS is offline!Please start it!\n");
                    wl->set_report_file_flag(false);
                    return;
                }
                if (wl->is_in_deleted_file_buffer(file_idx))
                {
                    continue;
                }
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    deleted_index_us.insert(file_idx);
                }
                log_err("Get file(%s) block:%ld failed!\n", root_cid.c_str(), check_block_idx);
                break;
            }
            // Validate hash
            sgx_sha256_hash_t got_hash;
            sgx_sha256_msg(p_sealed_data, sealed_data_size, &got_hash);
            if (p_sealed_data != NULL)
            {
                free(p_sealed_data);
            }
            uint8_t *leaf_hash_u = hex_string_to_bytes(leaf_hash.c_str(), leaf_hash.size());
            if (leaf_hash_u == NULL)
            {
                log_warn("Validate: Hexstring to bytes failed!Skip block:%ld check.\n", check_block_idx);
                continue;
            }
            if (memcmp(leaf_hash_u, got_hash, HASH_LENGTH) != 0)
            {
                if (status.get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    log_err("File(%s) Index:%ld block hash is not expected!\n", root_cid.c_str(), check_block_idx);
                    log_err("Get hash : %s\n", hexstring(got_hash, HASH_LENGTH));
                    log_err("Org hash : %s\n", leaf_hash.c_str());
                    deleted_index_us.insert(file_idx);
                }
                free(leaf_hash_u);
                break;
            }
            free(leaf_hash_u);
            spos = epos;
        }
    }

    // Change file status
    if (deleted_index_us.size() > 0)
    {
        sgx_thread_mutex_lock(&wl->file_mutex);
        for (auto index : deleted_index_us)
        {
            log_info("File status changed, hash: %s status: valid -> lost, will be deleted\n",
                    validate_sealed_files_m[index][FILE_CID].ToString().c_str());
            std::string cid = validate_sealed_files_m[index][FILE_CID].ToString();
            // Change file status
            if (validate_sealed_files_m[index][FILE_CHAIN_BLOCK_NUM].ToInt() >= wl->sealed_files[index][FILE_CHAIN_BLOCK_NUM].ToInt())
            {
                wl->sealed_files[index][FILE_STATUS].set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
                // Delete real file
                ocall_ipfs_del_all(&crust_status, cid.c_str());
                // Delete file tree structure
                persist_del(cid);
                // Reduce valid file
                wl->set_wl_spec(FILE_STATUS_VALID, -validate_sealed_files_m[index][FILE_SIZE].ToInt());
            }
        }
        sgx_thread_mutex_unlock(&wl->file_mutex);
    }
}
EOF
}

########## enc_srd_h_test ##########
function enc_srd_h_test()
{
    sed -i "/^#define SRD_MAX_PER_TURN 64/ c #define SRD_MAX_PER_TURN 1000" $enclave_srd_h
    sed -i "/crust_status_t change_srd_task(/ a size_t srd_decrease_test(long change);" $enclave_srd_h
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
    sgx_thread_mutex_lock(&wl->srd_mutex);
    wl->srd_path2hashs_m[path_str].push_back(p_hash_u);
    size_t srd_total_num = 0;
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    log_info("Seal random data -> %s, %luG success\n", hex_g_hash.c_str(), srd_total_num);
    sgx_thread_mutex_unlock(&wl->srd_mutex);

    // ----- Update srd info ----- //
    wl->set_srd_info(path_str, 1);
}

size_t srd_decrease_test(long change)
{
    Workload *wl = Workload::get_instance();
    uint32_t real_change = 0;
    uint32_t srd_total_num = 0;

    // Choose to be deleted g_hash index
    SafeLock sl(wl->srd_mutex);
    sl.lock();
    wl->deal_deleted_srd(false);
    // Set delete set
    for (auto it : wl->srd_path2hashs_m)
    {
        srd_total_num += it.second.size();
    }
    change = std::min(change, (long)srd_total_num);
    if (change == 0)
    {
        return 0;
    }
    // Sort path by srd number
    std::unordered_map<std::string, std::vector<uint8_t *>> srd_del_path2hashs_um;
    std::vector<std::pair<std::string, uint32_t>> ordered_srd_path2hashs_v;
    for (auto path2hashs: wl->srd_path2hashs_m)
    {
        ordered_srd_path2hashs_v.push_back(std::make_pair(path2hashs.first, path2hashs.second.size()));
    }
    std::sort(ordered_srd_path2hashs_v.begin(), ordered_srd_path2hashs_v.end(), 
        [](std::pair<std::string, uint32_t> &v1, std::pair<std::string, uint32_t> &v2)
        {
            return v1.second < v2.second;
        }
    );
    // Do delete
    size_t disk_num = wl->srd_path2hashs_m.size();
    for (auto it = ordered_srd_path2hashs_v.begin(); 
            it != ordered_srd_path2hashs_v.end() && change > 0 && disk_num > 0; it++, disk_num--)
    {
        std::string path = it->first;
        size_t del_num = change / disk_num;
        if ((double)change / (double)disk_num - (double)del_num > 0)
        {
            del_num++;
        }
        if (wl->srd_path2hashs_m[path].size() <= del_num)
        {
            del_num = wl->srd_path2hashs_m[path].size();
        }
        auto sit = wl->srd_path2hashs_m[path].begin();
        auto eit = sit + del_num;
        srd_del_path2hashs_um[path].insert(srd_del_path2hashs_um[path].end(), sit, eit);
        // Delete related srd from meta
        wl->srd_path2hashs_m[path].erase(sit, eit);
        // Delete related path if there is no srd
        if (wl->srd_path2hashs_m[path].size() == 0)
        {
            wl->srd_path2hashs_m.erase(path);
        }
        change -= del_num;
        real_change += del_num;
        wl->set_srd_info(path, -del_num);
    }
    sl.unlock();

    // ----- Delete corresponding items ----- //

    return real_change;
}
EOF
}

########## enc_wl_h_test ##########
function enc_wl_h_test()
{
cat << EOF > $TMPFILE

    void test_add_file(long file_num);
    void test_delete_file(uint32_t file_num);
    void test_delete_file_unsafe(uint32_t file_num);
EOF

    local spos=$(sed -n '/handle_report_result(/=' $enclave_workload_h)
    ((spos++))
    sed -i "$spos r $TMPFILE" $enclave_workload_h
    if [ $? -ne 0 ]; then
        echo "Replace enc_wl_h_test failed!"
        exit 1
    fi
}

########## enc_wl_cpp_test ##########
function enc_wl_cpp_test()
{
cat << EOF >> $enclave_workload_cpp

void Workload::test_add_file(long file_num)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
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
        uint8_t *p_cid_buffer = (uint8_t *)enc_malloc(CID_LENGTH / 2);
        sgx_read_rand(p_cid_buffer, CID_LENGTH / 2);
        file_entry_json[FILE_CID] = hexstring_safe(p_cid_buffer, CID_LENGTH / 2);
        file_entry_json[FILE_HASH] = reinterpret_cast<uint8_t *>(hash);
        file_entry_json[FILE_SIZE] = 10000;
        file_entry_json[FILE_SEALED_SIZE] = 9999;
        file_entry_json[FILE_BLOCK_NUM] = 1000;
        // Status indicates current new file's status, which must be one of valid, lost and unconfirmed
        file_entry_json[FILE_STATUS] = "100";
        free(p_cid_buffer);
        free(n_u);
        this->sealed_files.push_back(file_entry_json);
        this->set_wl_spec(FILE_STATUS_VALID, file_entry_json[FILE_SEALED_SIZE].ToInt());
        acc++;
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);
}

void Workload::test_delete_file(uint32_t file_num)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    if (this->sealed_files.size() == 0)
    {
        sgx_thread_mutex_unlock(&wl->file_mutex);
        return;
    }
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % this->sealed_files.size();
        auto status = &this->sealed_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) != FILE_STATUS_DELETED)
        {
            this->set_wl_spec(status->get_char(CURRENT_STATUS), -this->sealed_files[index][FILE_SEALED_SIZE].ToInt());
            status->set_char(CURRENT_STATUS, FILE_STATUS_DELETED);
            i++;
            j = 0;
        }
        else
        {
            j++;
        }
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);
}

void Workload::test_delete_file_unsafe(uint32_t file_num)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    file_num = std::min(this->sealed_files.size(), (size_t)file_num);
    this->sealed_files.erase(this->sealed_files.begin(), this->sealed_files.begin() + file_num);
    sgx_thread_mutex_unlock(&wl->file_mutex);

    sgx_thread_mutex_lock(&wl_spec_info_mutex);
    long ret = this->wl_spec_info["valid"]["num"].ToInt() - file_num;
    if (ret < 0)
    {
        this->wl_spec_info["valid"]["num"] = 0;
    }
    else
    {
        this->wl_spec_info["valid"]["num"] = ret;
    }
    sgx_thread_mutex_unlock(&wl_spec_info_mutex);
}
EOF

    local spos=$(sed -n "/this->report_has_validated_proof(/=" $enclave_workload_cpp)
    sed -i "$spos, $((spos+4)) d" $enclave_workload_cpp
    if [ $? -ne 0 ]; then
        echo "Replace enc_wl_cpp_test failed!"
        exit 1
    fi
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
    if [ $? -ne 0 ]; then
        echo "Replace enc_id_cpp_test failed!"
        exit 1
    fi

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
    if [ $? -ne 0 ]; then
        echo "Replace enc_id_cpp_test 2 failed!"
        exit 1
    fi

    pos=$(sed -n '/ocall_get_block_hash(/=' $enclave_identity_cpp)
    sed -i "$pos a \\\tsgx_read_rand(reinterpret_cast<uint8_t *>(report_hash), HASH_LENGTH);" $enclave_identity_cpp
    if [ $? -ne 0 ]; then
        echo "Replace enc_id_cpp_test 3 failed!"
        exit 1
    fi
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

void ocall_store_file_info_test(const char *info)
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
    if [ $? -ne 0 ]; then
        echo "Replace ocalls_cpp_test failed!"
        exit 1
    fi

    spos=$(sed -n '/ocall_validate_get_file(/=' $ocalls_cpp)
    ((spos+=3))
    local epos=$(sed -n "$spos,$ {/^\}/=}" $ocalls_cpp | head -n 1)
    sed -i "$spos,$((epos-1)) d" $ocalls_cpp
    if [ $? -ne 0 ]; then
        echo "Replace ocalls_cpp_test 2 failed!"
        exit 1
    fi
    sed -i "$((spos-=1)) r $TMPFILE" $ocalls_cpp

    spos=$(sed -n '/p_log->info("Sending work report:/=' $ocalls_cpp)
    sed -i "$((spos+1)),$((spos+8)) d" $ocalls_cpp
    if [ $? -ne 0 ]; then
        echo "Replace ocalls_cpp_test 3 failed!"
        exit 1
    fi

    sed -i "/p_log->info(\"Sending work report/ a \\\tEnclaveData::get_instance()->set_enclave_workreport(work_str);" $ocalls_cpp

    # Delete identity uploading process
    spos=$(sed -n '/\/\/ Send identity to crust chain/=' $ocalls_cpp)
    sed -i "$spos,$((spos+34)) d" $ocalls_cpp
    if [ $? -ne 0 ]; then
        echo "Replace ocalls_cpp_test 4 failed!"
        exit 1
    fi
}

########## ocalls_h_test ##########
function ocalls_h_test()
{
    sed -i '/ocall_store_upgrade_data(/a void ocall_store_file_info_test(const char *info);' $ocalls_h
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
async_cpp=$appdir/process/Async.cpp
async_h=$appdir/process/Async.h
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
async_cpp_test
async_h_test
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
