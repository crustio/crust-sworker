#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/shm.h>  // shared memory
#include <sys/sem.h>  // semaphore
#include <sys/msg.h>  // message queue
#include <string.h>
#include "Common.h"
#include "Resource.h"
#include "IPCReport.h"

#define WL_IPC_NUM  100
#define KP_IPC_NUM  101
#define MW_IPC_NUM  102

#define IPC_MK_TYPE(x)     (0x00000000|(x))

typedef enum _monitor_worker_msg_t {
    MW_MSG_ENTRYNETWORK = IPC_MK_TYPE(400),
    MW_MSG_ENTRYNETWORK_RES = IPC_MK_TYPE(401),
    MW_MSG_ENTRYCHAIN = IPC_MK_TYPE(402),
    MW_MSG_ENTRYCHAIN_RES = IPC_MK_TYPE(403),
    MW_MSG_ENTRYNETWORK_DATA = IPC_MK_TYPE(404),
    MW_MSG_ENTRYNETWORK_DATA_RES = IPC_MK_TYPE(405),
    MW_MSG_WORKER_PID = IPC_MK_TYPE(406),
    MW_MSG_WORKER_PID_RES = IPC_MK_TYPE(407),
    MW_MSG_MONITOR_PID = IPC_MK_TYPE(408),
    MW_MSG_MONITOR_PID_RES = IPC_MK_TYPE(409),
} monitor_worker_msg_t;

struct msg_form_t {
    long type;
    int text;
    attest_data_type_t data_type;
};

union semun
{
    int              val; /*for SETVAL*/
    struct semid_ds *buf;
    unsigned short  *array;
};

class Ipc {
    public:
        ~Ipc();
        bool init(const char* key_file_path, int key_num);

        key_t ipc_key = -1;
        int shmid = -1;
        int msqid = -1;
        int semid =-1;
        char *shm = NULL;
        struct shmid_ds shmid_ds_buf;
        struct msqid_ds msqid_ds_buf;
};

int sem_p(int sem_id);
int sem_v(int sem_id);
int del_sem(int sem_id);
void clean_ipc();
