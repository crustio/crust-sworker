#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/shm.h>  // shared memory
#include <sys/sem.h>  // semaphore
#include <sys/msg.h>  // message queue
#include <string.h>   // memcpy
#include "Common.h"   // memcpy

#define IPCTIMEOUT  5
#define WORKERTYPE  200
#define MONITORTYPE 201

struct msg_form {
    long type;
    char text;
};

union semun
{
    int              val; /*for SETVAL*/
    struct semid_ds *buf;
    unsigned short  *array;
};

int init_sem(int sem_id, int value);
int sem_p(int sem_id);
int sem_v(int sem_id);
int del_sem(int sem_id);
int creat_sem(key_t key);
int init_ipc();
int init_ipc_link();
int destroy_ipc();
int destroy_ipc_link();
int monitor_ipc(int sendtype, int recvtype);
int keep_worker_ipc();
void clean_ipc();
