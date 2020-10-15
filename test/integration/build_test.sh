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

void ecall_validate_srd()
{
    sched_add(SCHED_VALIDATE_SRD);
    validate_srd();
    sched_del(SCHED_VALIDATE_SRD);
}

void ecall_validate_file()
{
    sched_add(SCHED_VALIDATE_FILE);
    validate_meaningful_file();
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
EOF
}

########## enclave_edl_test ##########
function enclave_edl_test()
{
cat << EOF > $TMPFILE
		public void ecall_validate_srd();
		public void ecall_validate_file();
		public void ecall_store_metadata();

        public void ecall_test_add_file(long file_num);
        public void ecall_test_valid_file(uint32_t file_num);
        public void ecall_test_lost_file(uint32_t file_num);
        public void ecall_test_delete_file(uint32_t file_num);
EOF
    
    local pos=$(sed -n '/ecall_get_workload()/=' $enclave_edl)
    sed -i "$pos r $TMPFILE" $enclave_edl
}

########## ecalls_cpp_test ##########
function ecalls_cpp_test()
{
cat << EOF >$TMPFILE
	{"Ecall_validate_srd", 0},
	{"Ecall_validate_file", 0},
	{"Ecall_store_metadata", 0},
	{"Ecall_test_add_file", 1},
	{"Ecall_test_valid_file", 1},
	{"Ecall_test_lost_file", 1},
	{"Ecall_test_delete_file", 1},
EOF
    local pos=$(sed -n '/{"Ecall_delete_file", 0},/=' $ecalls_cpp)
    sed -i "$pos r $TMPFILE" $ecalls_cpp

cat << EOF >>$ecalls_cpp

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
EOF
}

########## ecalls_h_test ##########
function ecalls_h_test()
{
cat << EOF > $TMPFILE
sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid);
sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid);
sgx_status_t Ecall_store_metadata(sgx_enclave_id_t eid);

sgx_status_t Ecall_test_add_file(sgx_enclave_id_t eid, long file_num);
sgx_status_t Ecall_test_valid_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_lost_file(sgx_enclave_id_t eid, uint32_t file_num);
sgx_status_t Ecall_test_delete_file(sgx_enclave_id_t eid, uint32_t file_num);
EOF

    local pos=$(sed -n '/std::string show_enclave_thread_info();/=' $ecalls_h)
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
}

########## apihandler_h_test ##########
function apihandler_h_test()
{
cat << EOF > $TMPFILE

        cur_path = urlendpoint->base + "/report/work";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            crust_status_t crust_status = CRUST_SUCCESS;
            uint8_t *hash_u = (uint8_t *)malloc(32);
            int tmp_int;
            for (uint32_t i = 0; i < 32 / sizeof(tmp_int); i++)
            {
                tmp_int = rand();
                memcpy(hash_u + i * sizeof(tmp_int), &tmp_int, sizeof(tmp_int));
            }
            std::string block_hash = hexstring_safe(hash_u, 32);
            size_t block_height;
            memcpy(&block_height, hash_u, 32);
            free(hash_u);
            if (SGX_SUCCESS != Ecall_get_signed_work_report(global_eid, &crust_status,
                    block_hash.c_str(), block_height))
            {
                p_log->err("Get signed work report failed!\\n");
            }
            else
            {
                if (CRUST_SUCCESS == crust_status)
                {
                    // Send signed validation report to crust chain
                    std::string work_str = get_g_enclave_workreport();
                    res.body() = work_str;
                }
                else if (crust_status == CRUST_BLOCK_HEIGHT_EXPIRED)
                {
                    p_log->info("Block height expired.\\n");
                }
                else if (crust_status == CRUST_FIRST_WORK_REPORT_AFTER_REPORT)
                {
                    p_log->info("Can't generate work report for the first time after restart\\n");
                }
                else
                {
                    p_log->err("Get signed validation report failed! Error code: %x\\n", crust_status);
                }
            }
            goto getcleanup;
        }

        cur_path = urlendpoint->base + "/report/result";
        if (path.compare(cur_path) == 0)
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
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            Ecall_validate_srd(global_eid);
        }

        cur_path = urlendpoint->base + "/validate/file";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            Ecall_validate_file(global_eid);
        }

        cur_path = urlendpoint->base + "/store_metadata";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            Ecall_store_metadata(global_eid);
        }

        cur_path = urlendpoint->base + "/test/add_file";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            long file_num = req_json["file_num"].ToInt();
            Ecall_test_add_file(global_eid, file_num);
            res.body() = "Add file successfully!";
        }

        cur_path = urlendpoint->base + "/test/valid_file";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            long file_num = req_json["file_num"].ToInt();
            Ecall_test_valid_file(global_eid, file_num);
            res.body() = "Validate file successfully!";
        }

        cur_path = urlendpoint->base + "/test/lost_file";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_lost_file(global_eid, file_num);
            res.body() = "Lost file successfully!";
        }

        cur_path = urlendpoint->base + "/test/delete_file";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            json::JSON req_json = json::JSON::Load(req.body());
            uint32_t file_num = req_json["file_num"].ToInt();
            Ecall_test_delete_file(global_eid, file_num);
            res.body() = "Delete file successfully!";
        }
EOF

cat << EOF > $TMPFILE2

        cur_path = urlendpoint->base + "/srd/change_disk";
        if (path.compare(cur_path) == 0)
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

    # Srd directly
    pos=$(sed -n '/cur_path = urlendpoint->base + "\/srd\/change";/=' $apihandler_h)
    sed -i "$((pos+5)),$((pos+22))d" $apihandler_h
    sed -i "/Ecall_srd_set_change/c \\\t\t\t\tsrd_change(change_srd_num);" $apihandler_h

    # Seal 
    pos=$(sed -n '/cur_path = urlendpoint->base + "\/storage\/seal";/=' $apihandler_h)
    sed -i "$((pos+5)),$((pos+22))d" $apihandler_h

    # Unseal 
    pos=$(sed -n '/cur_path = urlendpoint->base + "\/storage\/unseal";/=' $apihandler_h)
    sed -i "$((pos+5)),$((pos+22))d" $apihandler_h

    # Confirm
    pos=$(sed -n '/cur_path = urlendpoint->base + "\/storage\/confirm";/=' $apihandler_h)
    sed -i "$((pos+5)),$((pos+22))d" $apihandler_h

    # Delete 
    pos=$(sed -n '/cur_path = urlendpoint->base + "\/storage\/delete";/=' $apihandler_h)
    sed -i "$((pos+5)),$((pos+22))d" $apihandler_h
}

########## enc_report_cpp_test ##########
function enc_report_cpp_test()
{
    local pos=$(sed -n '/crust_status_t get_signed_work_report(/=' $enclave_report_cpp)
    sed -i "$((pos+2)),$((pos+13))d" $enclave_report_cpp
}

########## enc_validate_cpp_test ##########
function enc_validate_cpp_test()
{
    sed -i -e "s/ocall_validate_init(/\/\/ocall_validate_init(/g" \
        -e "s/ocall_validate_close(/\/\/ocall_validate_close(/g" $enclave_validate_cpp
    local spos=$(sed -n '/dir_path = chose_entry->first;/=' $enclave_validate_cpp)
    local epos=$(sed -n '/\/\/ Compare leaf data/=' $enclave_validate_cpp)
    ((epos += 7))
    sed -i "$spos,$epos d" $enclave_validate_cpp

    spos=$(sed -n '/Get block data/=' $enclave_validate_cpp)
    epos=$(sed -n '/free(leaf_hash_u);/=' $enclave_validate_cpp | tail -n 1)
    sed -i "$spos,$epos d" $enclave_validate_cpp
}

########## enc_srd_cpp_test ##########
function enc_srd_cpp_test()
{
cat << EOF > $TMPFILE
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
EOF

    local spos=$(sed -n '/void srd_increase(/=' $enclave_srd_cpp)
    ((spos += 2))
    local epos=$(sed -n "$spos,$ {/^\}/=}" $enclave_srd_cpp | head -n 1)
    ((epos--))
    sed -i "$spos,$epos d" $enclave_srd_cpp
    sed -i "$((spos -= 1)) r $TMPFILE" $enclave_srd_cpp

    sed -i "s/ocall_delete_folder_or_file(/\/\/ocall_delete_folder_or_file(/g" $enclave_srd_cpp
}

function enc_wl_h_test()
{
cat << EOF > $TMPFILE

    void test_add_file(long file_num);
    void test_valid_file(uint32_t file_num);
    void test_lost_file(uint32_t file_num);
    void test_delete_file(uint32_t file_num);
EOF

    local spos=$(sed -n '/handle_report_result(/=' $enclave_workload_h)
    ((spos++))
    sed -i "$spos r $TMPFILE" $enclave_workload_h
}

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
        acc++;
    }
    sgx_thread_mutex_unlock(&g_checked_files_mutex);
}

void Workload::test_valid_file(uint32_t file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % this->checked_files.size();
        auto status = &this->checked_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_UNCONFIRMED
                || status->get_char(CURRENT_STATUS) == FILE_STATUS_LOST)
        {
            status->set_char(CURRENT_STATUS, FILE_STATUS_VALID);
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

void Workload::test_lost_file(uint32_t file_num)
{
    sgx_thread_mutex_lock(&g_checked_files_mutex);
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % this->checked_files.size();
        auto status = &this->checked_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            status->set_char(CURRENT_STATUS, FILE_STATUS_LOST);
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
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % this->checked_files.size();
        auto status = &this->checked_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) != FILE_STATUS_DELETED)
        {
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
EOF
}

function enc_srd_h_test()
{
    sed -i "/^#define SRD_MAX_PER_TURN 64/ c #define SRD_MAX_PER_TURN 1000" $enclave_srd_h
}

function enc_storage_cpp_test()
{
    sed -i "s/ocall_replace_file(/\/\/ocall_replace_file(/g" $enclave_storage_cpp
}

function enc_parameter_h_test()
{
    sed -i "/#define OCALL_STORE_THRESHOLD/ c #define OCALL_STORE_THRESHOLD 1024" $enclave_parameter_h
}

########## ocalls_cpp_test ##########
function ocalls_cpp_test()
{
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
}

function InstallAPP()
{
    mkdir -p $testdir
    mkdir -p $testdir/bin
    mkdir -p $testdir/etc
    mkdir -p $testdir/files
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
devrootdir=$(cd $basedir/../..;pwd)
scriptdir=$basedir/scripts
srcdir=$basedir/src
appdir=$srcdir/app
encdir=$srcdir/enclave
enclave_cpp=$encdir/Enclave.cpp
enclave_edl=$encdir/Enclave.edl
ecalls_cpp=$appdir/ecalls/ECalls.cpp
ecalls_h=$appdir/ecalls/ECalls.h
process_cpp=$appdir/process/Process.cpp
resource_h=$appdir/include/Resource.h
apihandler_h=$appdir/http/ApiHandler.h
ocalls_cpp=$appdir/ocalls/OCalls.cpp
enclave_report_cpp=$encdir/report/Report.cpp
enclave_validate_cpp=$encdir/validator/Validator.cpp
enclave_srd_cpp=$encdir/srd/Srd.cpp
enclave_srd_h=$encdir/srd/Srd.h
enclave_storage_cpp=$encdir/storage/Storage.cpp
enclave_parameter_h=$encdir/include/Parameter.h
enclave_workload_cpp=$encdir/workload/Workload.cpp
enclave_workload_h=$encdir/workload/Workload.h
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
    sudo apt-get install jq
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
apihandler_h_test
ocalls_cpp_test
enclave_cpp_test
enclave_edl_test
enc_report_cpp_test
enc_validate_cpp_test
enc_srd_cpp_test
enc_srd_h_test
enc_wl_cpp_test
enc_wl_h_test
#enc_storage_cpp_test
#enc_parameter_h_test

InstallAPP
