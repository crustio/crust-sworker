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
EOF
}

########## enclave_edl_test ##########
function enclave_edl_test()
{
    local pos=$(sed -n '/ecall_get_workload()/=' $enclave_edl)
    sed -i -e "$pos a \\\t\tpublic void ecall_validate_srd();" \
        -e "$pos a \\\t\tpublic void ecall_validate_file();" \
        -e "$pos a \\\t\tpublic void ecall_store_metadata();" $enclave_edl
}

########## ecalls_cpp_test ##########
function ecalls_cpp_test()
{
    local pos=$(sed -n '/{"Ecall_delete_file", 0},/=' $ecalls_cpp)
    sed -i -e "$pos a \\\t{\"Ecall_validate_srd\", 0}," \
        -e "$pos a \\\t{\"Ecall_validate_file\", 0}," \
        -e "$pos a \\\t{\"Ecall_store_metadata\", 0}," $ecalls_cpp

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
EOF
}

########## ecalls_h_test ##########
function ecalls_h_test()
{
    local pos=$(sed -n '/std::string show_enclave_thread_info();/=' $ecalls_h)
    sed -i -e "$pos a sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid);" \
        -e "$pos a sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid);" \
        -e "$pos a sgx_status_t Ecall_store_metadata(sgx_enclave_id_t eid);" $ecalls_h
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
                    p_log->info("Sign validation report successfully!\\n%s\\n", work_str.c_str());
                    res.body() = work_str;
                    // Delete space and line break
                    remove_char(work_str, '\\\\');
                    remove_char(work_str, '\\n');
                    remove_char(work_str, ' ');
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

        cur_path = urlendpoint->base + "/report/order";
        if (memcmp(path.c_str(), cur_path.c_str(), cur_path.size()) == 0)
        {
            crust_status_t crust_status = CRUST_SUCCESS;
            if(SGX_SUCCESS != Ecall_get_signed_order_report(global_eid, &crust_status)
                || CRUST_SUCCESS != crust_status)
            {
                if (CRUST_REPORT_NO_ORDER_FILE != crust_status)
                {
                    p_log->err("Get signed order report failed! Error code: %x\\n", crust_status);
                }
            }
            else
            {
                p_log->info("Get order report:%s\\n", get_g_order_report().c_str());
            }
            set_g_order_report("");
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
    sed -i "$((pos+2)),$((pos+21))d" $enclave_report_cpp
}

########## enc_validate_cpp_test ##########
function enc_validate_cpp_test()
{
    sed -i -e "s/ocall_validate_init(/\/\/ocall_validate_init(/g" \
        -e "s/ocall_validate_close(/\/\/ocall_validate_close(/g" $enclave_validate_cpp
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
    sed -i -e "/\"base_path\" :/c \\\t\"base_path\" : \"$testdir/<VERSION>/tee_base_path\"," \
        -e "/\"srd_paths\" :/c \\\t\"srd_paths\" : []," $configfile
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

InstallAPP
