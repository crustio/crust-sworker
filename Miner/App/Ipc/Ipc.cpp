#include "Ipc.h"

key_t ipc_key = -1;
int shmid=-1, semid=-1, msqid=-1;
char *shm = NULL;
struct shmid_ds buf1;
struct msqid_ds buf2;
struct msg_form msg;

/**
 * @description: Init semaphore
 * @return: Initial status
 * */
int init_sem(int sem_id, int value)
{
    union semun tmp;
    tmp.val = value;
    if(semctl(sem_id, 0, SETVAL, tmp) == -1)
    {
        perror("Init Semaphore Error");
        return -1;
    }
    return 0;
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
 * @description: Create semaphore
 * @return: Create status
 * */
int creat_sem(key_t key)
{
    int sem_id;
    if((sem_id = semget(key, 1, IPC_CREAT|0666)) == -1)
    {
        perror("semget error");
        exit(-1);
    }
    init_sem(sem_id, 1);
    return sem_id;
}

/**
 * @description: Init monitor IPC, including creating shared memory,
 *  message queue and sem
 * @return: 0 for success while other for fail
 * */
int init_ipc()
{
    // Get IPC key
    if((ipc_key = ftok(IPC_FILE_PATH, 'z')) < 0)
    {
        cfprintf(NULL, CF_ERROR "ftok error\n");
        return -1;
    }

    // Create shared memory
    if((shmid = shmget(ipc_key, 1024, IPC_CREAT|0666)) == -1)
    {
        cfprintf(NULL, CF_ERROR "Create Shared Memory Error\n");
        return -1;
    }

    // Link shared memory to current process
    shm = (char*)shmat(shmid, 0, 0);
    //if(shm == -1)
    if(shm == NULL)
    {
        cfprintf(NULL, CF_ERROR "Attach Shared Memory Error\n");
        return -1;
    }

    // Create message queue
    if((msqid = msgget(ipc_key, IPC_CREAT|0777)) == -1)
    {
        cfprintf(NULL, CF_ERROR "msgget error\n");
        return -1;
    }

    // Get semaphore
	if((semid = semget(ipc_key, 0, 0)) == -1)
    {
        semid = creat_sem(ipc_key);
        //cfprintf(NULL, CF_ERROR "semget error");
        //return -1;
    }

    return 0;
}

/**
 * @description: Used to delete previous ipc variable
 * */
void clean_ipc()
{
    // Get ipc key, same file and flag result in same ipc key
    if((ipc_key = ftok(IPC_FILE_PATH, 'z')) < 0)
    {
        return;
    }

    // Get lasttime message queue
    if((msqid = msgget(ipc_key, 0)) == -1)
    {
        return;
    }

    msgctl(msqid, IPC_RMID, &buf2);
}

/**
 * @description: Recycle message queue, semaphore and shared memory
 * @return: Destroy status
 * */
int destroy_ipc()
{
    if(shmid != -1)
    {
	    shmctl(shmid, IPC_RMID, &buf1);
    }
    if(msqid != -1)
    {
        msgctl(msqid, IPC_RMID, &buf2);
    }
    if(semid != -1)
    {
        del_sem(semid);
    }
    return 1;
}
