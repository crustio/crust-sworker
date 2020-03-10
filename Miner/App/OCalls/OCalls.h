#ifndef _OCALLS_APP_H_
#define _OCALLS_APP_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include "Ipfs.h"
#include "FileUtils.h"
#include "FormatUtils.h"
#include "Common.h"
#include "Ipc.h"
#include "IPCReport.h"

#define HEXSTRING_BUF 128
#define BUFSIZE 1024
#define IPC_TIMEOUT 30

extern FILE *felog;

extern Ipc *g_wl_ipc;
extern Ipc *g_kp_ipc;

// Used to store ocall file data
unsigned char *ocall_file_data = NULL;

/**
 * @description: ocall for printing string
 * @param str -> string for printing
 */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/**
 * @description: ocall for cprintf string
 * @param str -> string for printing
 */
void ocall_eprint_string(const char *str)
{
    cprintf_info(felog, "%s", str);
}

/**
 * @description: ocall for creating directory
 * @param path -> the path of directory
 */
void ocall_create_dir(const char *path)
{
    std::vector<std::string> fields;
    boost::split(fields, path, boost::is_any_of("/"));
    std::string current_path = "";

    for (size_t i = 0; i < fields.size(); i++)
    {
        if (access((current_path + fields[i]).c_str(), 0) == -1)
        {
            mkdir((current_path + fields[i]).c_str(), S_IRWXU);
        }

        current_path += fields[i] + "/";
    }
}

/**
 * @description: ocall for renaming directory
 * @param old_path -> the old path of directory
 * @param new_path -> the new path of directory
 */
void ocall_rename_dir(const char *old_path, const char *new_path)
{
    if (access(old_path, 0) != -1)
    {
        rename(old_path, new_path);
    }
}

/**
 * @description: ocall for saving data into file
 * @param file_path -> file path for saving
 * @param data -> data for saving
 * @param len -> the length of data
 */
void ocall_save_file(const char *file_path, const unsigned char *data, size_t len)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
    out.write(reinterpret_cast<const char *>(data), len);
    out.close();
}

/**
 * @description: ocall for geting folders number under directory
 * @param path -> the path of directory
 * @return the number of folders
 */
size_t ocall_get_folders_number_under_path(const char *path)
{
    if (access(path, 0) != -1)
    {
        return get_folders_under_path(std::string(path)).size();
    }
    else
    {
        return 0;
    }
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path -> the path of file
 * @param len -> the length of data
 * @return file data
 */

void ocall_get_file(const char *file_path, unsigned char **p_file, size_t *len)
{
    if (access(file_path, 0) == -1)
    {
        return;
    }

    std::ifstream in;

    in.open(file_path, std::ios::out | std::ios::binary);

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    if (ocall_file_data != NULL)
    {
        delete[] ocall_file_data;
    }

    ocall_file_data = new unsigned char[*len];

    in.read(reinterpret_cast<char *>(ocall_file_data), *len);
    in.close();

    *p_file = ocall_file_data;
}

/**
 * @description: ocall for getting merkle tree by root hash
 * @param root_hash -> the root hash of file
 * @return: the merkle tree of file
 */
void ocall_get_merkle_tree(const char *root_hash, MerkleTree **p_merkletree)
{
    //return get_ipfs()->get_merkle_tree(root_hash);
    *p_merkletree = get_ipfs()->get_merkle_tree(root_hash);
}

/**
 * @description: ocall for getting block data from ipfs by block hash
 * @param hash -> the block hash
 * @param len(out) -> the length of block data 
 * @return: the block data
 */
void ocall_get_block(const char *hash, size_t *len, unsigned char **p_block)
{
    //return get_ipfs()->get_block_data(hash, len);
    *p_block = get_ipfs()->get_block_data(hash, len);
}

/**
 * @description: ocall for getting changed files
 * @return: changed files
 */
void ocall_get_diff_files(Node **node)
{
    get_ipfs()->generate_diff_files();
    *node = get_ipfs()->get_diff_files();
}

/**
 * @description: ocall for getting the number of changed files
 * @return: the number of changed files
 */
size_t ocall_get_diff_files_num()
{
    return get_ipfs()->get_diff_files_num();
}

/**
 * @description: ocall for wait
 * @param u microsecond
 */
void ocall_usleep(int u)
{
    usleep(u);
}

/**
 * @description: message receive function wrapper to do timeout check
 * @return: receive status
 * */
int Msgrcv_to(int msgqid, void *msgp, size_t msgsz, long msgtype)
{
    ssize_t res = 0;
    int timeout = 0;
    while ((res = msgrcv(msgqid, msgp, msgsz, msgtype, IPC_NOWAIT)) == -1 && timeout < IPC_TIMEOUT)
    {
        timeout++;
        sleep(1);
    }
    return (int)res;
}

/**
 * @description: Get current ipc based on data type
 * @return: current ipc
 * */
Ipc *get_current_ipc(attest_data_type_t data_type)
{
    if (data_type == ATTEST_DATATYPE_KEYPAIR)
    {
        return g_kp_ipc;
    }
    else if (data_type == ATTEST_DATATYPE_WORKLOAD)
    {
        return g_wl_ipc;
    }
    else
    {
        cprintf_err(felog, "Wrong data type!\n");
    }

    return NULL;
}

/**
 * @description: Worker process sends session request and receives Message1
 * @return: ocall status
 * */
ipc_status_t ocall_send_request_recv_msg1(sgx_dh_msg1_t *dh_msg1, uint32_t secret_size, attest_data_type_t data_type)
{
    // Request session to monitor process
    //cprintf_info(felog, "attest session ===> Sending session request:secret size:%d\n", secret_size);
    Ipc *cur_ipc = get_current_ipc(data_type);
    sem_p(cur_ipc->semid);
    memcpy(cur_ipc->shm, "SessionRequest", 20);
    sem_v(cur_ipc->semid);
    msg_form_t msg;
    msg.type = 100;
    msg.text = secret_size;
    msg.data_type = data_type;
    int send_len = sizeof(msg.text) + sizeof(msg.data_type);
    if (msgsnd(cur_ipc->msqid, &msg, send_len, 0) == -1)
    {
        return IPC_SENDMSG_ERROR;
    }

    // Read Message1
    //cprintf_info(felog, "attest session ===> Waiting for msg1\n");
    if (Msgrcv_to(cur_ipc->msqid, &msg, sizeof(msg.text), 101) == -1)
    {
        return IPC_RECVMSG_ERROR;
    }
    sem_p(cur_ipc->semid);
    memcpy(dh_msg1, cur_ipc->shm, sizeof(sgx_dh_msg1_t));
    sem_v(cur_ipc->semid);
    //cprintf_info(felog, "attest session ===> Get msg1.\n");

    return IPC_SUCCESS;
}

/**
 * @description: Monitor process receives session request
 * @return: ocall status
 * */
ipc_status_t ocall_recv_session_request(char *request, uint32_t *secret_size, attest_data_type_t data_type)
{
    // Waiting for session request
    int retry = 3;
    //cprintf_info(felog, "attest session ===> Waiting for session request\n");
    Ipc *cur_ipc = get_current_ipc(data_type);
    msg_form_t msg;
    int recv_len = sizeof(msg.text) + sizeof(msg.data_type);
    do
    {
        if (Msgrcv_to(cur_ipc->msqid, &msg, recv_len, 100) == -1)
        {
            return IPC_RECVMSG_ERROR;
        }
        if (msg.data_type == data_type)
        {
            memcpy(secret_size, &msg.text, sizeof(msg.text));
            //cprintf_info(felog, "attest session ===> secret size:%d\n", *secret_size);
            sem_p(cur_ipc->semid);
            memcpy(request, cur_ipc->shm, 20);
            sem_v(cur_ipc->semid);
            if (strcmp(request, "SessionRequest") == 0)
            {
                //cprintf_info(felog, "attest session ===> Get session request.\n");
                break;
            }
        }
        sleep(3);
    } while (--retry > 0);

    return IPC_SUCCESS;
}

/**
 * @description: Monitor process sends Message1 and receives Message2
 * @return: ocall status
 * */
ipc_status_t ocall_send_msg1_recv_msg2(sgx_dh_msg1_t *dh_msg1, sgx_dh_msg2_t *dh_msg2, attest_data_type_t data_type)
{
    // Send Message1 to worker
    //cprintf_info(felog, "attest session ===> Sending msg1.\n");
    Ipc *cur_ipc = get_current_ipc(data_type);
    sem_p(cur_ipc->semid);
    memcpy(cur_ipc->shm, dh_msg1, sizeof(sgx_dh_msg1_t));
    sem_v(cur_ipc->semid);
    msg_form_t msg;
    msg.type = 101;
    if (msgsnd(cur_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        return IPC_SENDMSG_ERROR;
    }

    // Receive Message2 from worker
    //cprintf_info(felog, "attest session ===> Waiting for msg2\n");
    if (Msgrcv_to(cur_ipc->msqid, &msg, sizeof(msg.text), 102) == -1)
    {
        return IPC_RECVMSG_ERROR;
    }
    sem_p(cur_ipc->semid);
    memcpy(dh_msg2, cur_ipc->shm, sizeof(sgx_dh_msg2_t));
    sem_v(cur_ipc->semid);
    //cprintf_info(felog, "attest session ===> Get msg2.\n");

    return IPC_SUCCESS;
}

/**
 * @description: Worker process sends Message2 and receives Message3
 * @return: ocall status
 * */
ipc_status_t ocall_send_msg2_recv_msg3(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, attest_data_type_t data_type)
{
    // Send Message2 to Monitor
    //cprintf_info(felog, "attest session ===> Sending msg2.\n");
    Ipc *cur_ipc = get_current_ipc(data_type);
    sem_p(cur_ipc->semid);
    memcpy(cur_ipc->shm, dh_msg2, sizeof(sgx_dh_msg2_t));
    sem_v(cur_ipc->semid);
    msg_form_t msg;
    msg.type = 102;
    if (msgsnd(cur_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        return IPC_SENDMSG_ERROR;
    }

    // Receive Message3 from worker
    //cprintf_info(felog, "attest session ===> Waiting for msg3\n");
    if (Msgrcv_to(cur_ipc->msqid, &msg, sizeof(msg.text), 103) == -1)
    {
        return IPC_RECVMSG_ERROR;
    }
    sem_p(cur_ipc->semid);
    memcpy(dh_msg3, cur_ipc->shm, sizeof(sgx_dh_msg3_t));
    sem_v(cur_ipc->semid);
    //cprintf_info(felog, "attest session ===> Get msg3.\n");

    return IPC_SUCCESS;
}

/**
 * @description: Monitor process sends Message1 and receives Message2
 * @return: ocall status
 * */
ipc_status_t ocall_send_msg3(sgx_dh_msg3_t *dh_msg3, attest_data_type_t data_type)
{
    // Send Message3 to worker
    //cprintf_info(felog, "attest session ===> Sending msg3.\n");
    Ipc *cur_ipc = get_current_ipc(data_type);
    sem_p(cur_ipc->semid);
    memcpy(cur_ipc->shm, dh_msg3, sizeof(sgx_dh_msg3_t));
    sem_v(cur_ipc->semid);
    msg_form_t msg;
    msg.type = 103;
    if (msgsnd(cur_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        return IPC_SENDMSG_ERROR;
    }

    return IPC_SUCCESS;
}

/**
 * @description: Worker process sends encrypted tee key pair to monitor process
 * @return: ocall status
 * */
ipc_status_t ocall_send_secret(sgx_aes_gcm_data_t *req_message, uint32_t len, attest_data_type_t data_type)
{
    //cprintf_info(felog, "attest session ===> Sending secret(len:%d)\n", len);
    Ipc *cur_ipc = get_current_ipc(data_type);
    sem_p(cur_ipc->semid);
    memcpy(cur_ipc->shm, req_message, len);
    sem_v(cur_ipc->semid);
    msg_form_t msg;
    msg.type = 104;
    if (msgsnd(cur_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        return IPC_SENDMSG_ERROR;
    }

    if (Msgrcv_to(cur_ipc->msqid, &msg, sizeof(msg.text), 105) == -1)
    {
        return IPC_RECVMSG_ERROR;
    }

    return IPC_SUCCESS;
}

/**
 * @description: Monitor process receives encrypted tee key pair 
 * @return: ocall status
 * */
ipc_status_t ocall_recv_secret(sgx_aes_gcm_data_t *req_message, uint32_t len, attest_data_type_t data_type)
{
    //cprintf_info(felog, "attest session ===> Waiting for secret\n");
    Ipc *cur_ipc = get_current_ipc(data_type);
    msg_form_t msg;
    if (Msgrcv_to(cur_ipc->msqid, &msg, sizeof(msg.text), 104) == -1)
    {
        return IPC_RECVMSG_ERROR;
    }
    sem_p(cur_ipc->semid);
    memcpy(req_message, cur_ipc->shm, len);
    sem_v(cur_ipc->semid);

    msg.type = 105;
    if (msgsnd(cur_ipc->msqid, &msg, sizeof(msg.text), 0) == -1)
    {
        return IPC_SENDMSG_ERROR;
    }

    return IPC_SUCCESS;
}

#endif /* !_OCALLS_APP_H_ */
