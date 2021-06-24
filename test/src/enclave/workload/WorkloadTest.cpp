#include "WorkloadTest.h"

WorkloadTest *WorkloadTest::workloadTest = NULL;

WorkloadTest *WorkloadTest::get_instance()
{
    if (WorkloadTest::workloadTest == NULL)
    {
        WorkloadTest::workloadTest = new WorkloadTest();
    }

    return WorkloadTest::workloadTest;
}

void WorkloadTest::test_add_file(long file_num)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    long acc = 0;
    for (long i = 0; i < file_num; i++)
    {
        uint8_t *n_u = new uint8_t[32];
        sgx_read_rand(n_u, HASH_LENGTH);
        sgx_sha256_hash_t hash;
        sgx_sha256_msg(n_u, HASH_LENGTH, &hash);
        json::JSON file_entry_json;
        uint8_t *p_cid_buffer = (uint8_t *)enc_malloc(CID_LENGTH / 2);
        sgx_read_rand(p_cid_buffer, CID_LENGTH / 2);
        std::string cid = hexstring_safe(p_cid_buffer, CID_LENGTH / 2);
        file_entry_json[FILE_CID] = cid;
        file_entry_json[FILE_HASH] = reinterpret_cast<uint8_t *>(hash);
        file_entry_json[FILE_SIZE] = 100000000;
        file_entry_json[FILE_SEALED_SIZE] = 999900000;
        file_entry_json[FILE_BLOCK_NUM] = 100000000;
        file_entry_json[FILE_CHAIN_BLOCK_NUM] = 100000000;
        // Status indicates current new file's status, which must be one of valid, lost and unconfirmed
        file_entry_json[FILE_STATUS] = "100000000000";
        free(p_cid_buffer);
        free(n_u);
        wl->add_file_nolock(file_entry_json);
        wl->set_file_spec(FILE_STATUS_VALID, file_entry_json[FILE_SEALED_SIZE].ToInt());

        std::string file_info;
        file_info.append("{ \\\"" FILE_SIZE "\\\" : ").append(std::to_string(file_entry_json[FILE_SIZE].ToInt())).append(" , ")
            .append("\\\"" FILE_SEALED_SIZE "\\\" : ").append(std::to_string(file_entry_json[FILE_SEALED_SIZE].ToInt())).append(" , ")
            .append("\\\"" FILE_CHAIN_BLOCK_NUM "\\\" : ").append(std::to_string(1111)).append(" }");
        ocall_store_file_info(cid.c_str(), file_info.c_str(), FILE_TYPE_VALID);

        acc++;
    }
    sgx_thread_mutex_unlock(&wl->file_mutex);
}

void WorkloadTest::test_delete_file(uint32_t file_num)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    if (wl->sealed_files.size() == 0)
    {
        sgx_thread_mutex_unlock(&wl->file_mutex);
        return;
    }
    for (uint32_t i = 0, j = 0; i < file_num && j < 200;)
    {
        uint32_t index = 0;
        sgx_read_rand(reinterpret_cast<uint8_t *>(&index), sizeof(uint32_t));
        index = index % wl->sealed_files.size();
        auto status = &wl->sealed_files[index][FILE_STATUS];
        if (status->get_char(CURRENT_STATUS) != FILE_STATUS_DELETED)
        {
            wl->set_file_spec(status->get_char(CURRENT_STATUS), -wl->sealed_files[index][FILE_SEALED_SIZE].ToInt());
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

void WorkloadTest::test_delete_file_unsafe(uint32_t file_num)
{
    Workload *wl = Workload::get_instance();
    sgx_thread_mutex_lock(&wl->file_mutex);
    file_num = std::min(wl->sealed_files.size(), (size_t)file_num);
    wl->sealed_files.erase(wl->sealed_files.begin(), wl->sealed_files.begin() + file_num);
    sgx_thread_mutex_unlock(&wl->file_mutex);

    wl->clean_wl_file_spec();
}
