#include "Ipc.h"

extern FILE *felog;

Ipc::~Ipc()
{
    struct shmid_ds buf1;
    struct msqid_ds buf2;
    if(this->shmid != -1)
    {
	    shmctl(this->shmid, IPC_RMID, &buf1);
    }
    if(this->msqid != -1)
    {
        msgctl(this->msqid, IPC_RMID, &buf2);
    }
    if(this->semid != -1)
    {
        del_sem(this->semid);
    }
}

bool Ipc::init(const char* key_file_path, int key_num)
{
    if(key_num < 0 || key_num > 255)
    {
        cprintf_err(felog, "Invalid generate_num\n");
        return false;
    }

    // Get IPC key
    if((this->ipc_key = ftok(key_file_path, key_num)) < 0)
    {
        cprintf_err(felog, "ftok ipc error\n");
        return false;
    }

    // Create shared memory
    if((this->shmid = shmget(this->ipc_key, 1024, IPC_CREAT|0666)) == -1)
    {
        cprintf_err(felog, "Create Shared Memory Error\n");
        return false;
    }

    // Link shared memory to current process
    this->shm = (char*)shmat(this->shmid, 0, 0);
    if(this->shm == NULL)
    {
        cprintf_err(felog, "Attach Shared Memory Error\n");
        return false;
    }

    // Create message queue for attestation
    if((this->msqid = msgget(this->ipc_key, IPC_CREAT|0777)) == -1)
    {
        cprintf_err(felog, "msgget error\n");
        return false;
    }

    /* Create semaphore */
    if((this->semid = semget(this->ipc_key, 1, IPC_CREAT|0666)) == -1)
    {
        perror("semget error");
        return false;
    }
    // init semaphore
    union semun tmp;
    tmp.val = 1;
    if(semctl(this->semid, 0, SETVAL, tmp) == -1)
    {
        perror("Init Semaphore Error");
        return false;
    }

    return true;
}

/**
 * @description: Semaphore P operation
 * @return: Operation status
 * */
int sem_p(int sem_id)
{
    struct sembuf sbuf;
    sbuf.sem_num = 0;
    sbuf.sem_op = -1;
    sbuf.sem_flg = SEM_UNDO;

    if(semop(sem_id, &sbuf, 1) == -1)
    {
        perror("P operation Error");
        return -1;
    }
    return 0;
}

/**
 * @description: Semaphore V operation
 * @return: Operation status
 * */
int sem_v(int sem_id)
{
    struct sembuf sbuf;
    sbuf.sem_num = 0;
    sbuf.sem_op = 1;
    sbuf.sem_flg = SEM_UNDO;

    if(semop(sem_id, &sbuf, 1) == -1)
    {
        perror("V operation Error");
        return -1;
    }
    return 0;
}

/**
 * @description: Delete semaphore
 * @return: Delete status
 * */
int del_sem(int sem_id)
{
    union semun tmp;
    if(semctl(sem_id, 0, IPC_RMID, tmp) == -1)
    {
        perror("Delete Semaphore Error");
        return -1;
    }
    return 0;
}

/**
 * @description: Used to delete previous ipc variable
 * */
void clean_ipc()
{
    int ipc_key = -1;
    int msqid = -1;
    struct msqid_ds buf;
    // Delete workload ipc
    // Get ipc key, same file and flag result in same ipc key
    if((ipc_key = ftok(WL_FILE_PATH, WL_IPC_NUM)) >= 0)
    {
        // Get lasttime message queue
        if((msqid = msgget(ipc_key, 0)) != -1)
        {
            msgctl(msqid, IPC_RMID, &buf);
        }
    }

    // Delete key pair ipc
    // Get ipc key, same file and flag result in same ipc key
    if((ipc_key = ftok(KP_FILE_PATH, KP_IPC_NUM)) >= 0)
    {
        // Get lasttime message queue
        if((msqid = msgget(ipc_key, 0)) != -1)
        {
            msgctl(msqid, IPC_RMID, &buf);
        }
    }

    // Delete monitor worker ipc
    // Get ipc key, same file and flag result in same ipc key
    if((ipc_key = ftok(MW_FILE_PATH, MW_IPC_NUM)) >= 0)
    {
        // Get lasttime message queue
        if((msqid = msgget(ipc_key, 0)) != -1)
        {
            msgctl(msqid, IPC_RMID, &buf);
        }
    }

}
