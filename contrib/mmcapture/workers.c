/* workers.c
 *
 * This file contains functions used for thread workers.
 *
 * File begun on 2019-12-06
 *
 * Created by:
 *  - Théo Bertin (theo.bertin@advens.fr)
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "workers.h"

static inline void addWorkerToConfList(Worker *worker, WorkersCnf *conf) {
    DBGPRINTF("addWorkerToConfList, tid: %ld\n", worker->tid);

    if(conf->workersListHead) {
        worker->next = conf->workersListHead;
        conf->workersListHead->prev = worker;
        worker->prev = NULL;
    }
    else {
        worker->next = NULL;
        worker->prev = NULL;
    }
    conf->workersListHead = worker;
    conf->workersNumber++;
    return;
}

static inline void removeWorkerFromConfList(Worker *worker, WorkersCnf *conf) {
    DBGPRINTF("removeWorkerFromConfList, tid: %ld\n", worker->tid);

    if(worker->next) worker->next->prev = worker->prev;
    if(worker->prev) worker->prev->next = worker->next;
    if(conf->workersListHead == worker) conf->workersListHead = worker->next;
    conf->workersNumber--;
    return;
}

static inline void *workerWaitWork(void *pData) {
    Worker *self = (Worker *)pData;
    DBGPRINTF("workerWaitWork, tid: %ld\n", self->tid);

    pthread_mutex_lock(&(self->mSignal));
    while(1) {
        DBGPRINTF("worker [%ld] waiting for work\n", self->tid);
        pthread_cond_wait(&(self->cSignal), &(self->mSignal));
        DBGPRINTF("worker [%ld] got work to do\n", self->tid);

        if(self->signal.bWork) {
            DBGPRINTF("launching function for worker %ld\n", self->tid);
            self->workFunction(self->pData);
            self->signal.bWork = 0;
            free(self->pData);
        }
        else if(self->signal.bClose) {
            DBGPRINTF("closing worker\n");
            break;
        }
    }

    pthread_mutex_unlock(&(self->mSignal));
    pthread_exit(0);
}

static inline int stopWorker(Worker *worker) {
    DBGPRINTF("stopWorker, tid: %ld\n", worker->tid);
    void *status;

    pthread_mutex_lock(&(worker->mSignal));
    worker->signal.bClose = 1;
    pthread_cond_signal(&(worker->cSignal));
    pthread_mutex_unlock(&(worker->mSignal));

    pthread_join(worker->thread, &status);
    return (int)status;
}

static inline int startWorker(Worker *worker) {
    DBGPRINTF("startWorker, tid: %ld\n", worker->tid);
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if(pthread_create(&(worker->thread), &attr, workerWaitWork, (void *)worker) != 0) {
        worker->thread = NULL;
        pthread_attr_destroy(&attr);
        return -1;
    }

    pthread_attr_destroy(&attr);
    return 0;
}

static inline Worker *createWorker(WorkersCnf *conf) {
    DBGPRINTF("createWorker\n");
    Worker *retWorker = NULL;
    if(conf && conf->workersNumber < conf->maxWorkers) {
        retWorker = calloc(1, sizeof(Worker));
        retWorker->tid = conf->workersNumber+1;
    }
    else {
        DBGPRINTF("will not create new worker, max number reached\n");
    }

    return retWorker;
}

/**
 * worker's mutex should be unlocked, worker itself should be closed and thread exited
 * @param worker
 */
static inline void deleteWorker(Worker *worker) {
    DBGPRINTF("deleteWorker, tid: %ld\n", worker->tid);
    pthread_mutex_destroy(&(worker->mSignal));
    pthread_cond_destroy(&(worker->cSignal));
    free(worker);
}

int addWorkerToConf(WorkersCnf *conf) {
    DBGPRINTF("addWorkerToConf\n");
    Worker *new = createWorker(conf);

    if(new) {
        if(conf->workFunction)  new->workFunction = conf->workFunction;
        addWorkerToConfList(new, conf);
        return startWorker(new);
    }

    return -1;
}

int removeWorkerFromConf(Worker *worker, WorkersCnf *conf) {
    DBGPRINTF("removeWorkerFromConf, tid: %ld\n", worker->tid);

    if(stopWorker(worker) == 0) {
        removeWorkerFromConfList(worker, conf);
        deleteWorker(worker);

        return 0;
    }

    return -1;
}

void addWork(WorkerData *work, Synchroniser *synchroniser) {
    DBGPRINTF("addWork\n");

    pthread_mutex_lock(&(synchroniser->mSignal));

    if(!synchroniser->pDataListHead)    synchroniser->pDataListHead = work;
    if(synchroniser->pDataListTail)     synchroniser->pDataListTail->next = work;
    synchroniser->pDataListTail = work;
    synchroniser->listSize++;
    synchroniser->signal.bWork |= 1;

    pthread_cond_signal(&(synchroniser->cSignal));
    pthread_mutex_unlock(&(synchroniser->mSignal));

    return;
}

/**
 * synchroniser's mutex SHOULD be locked before calling function
 * @param synchroniser
 * @return
 */
static inline WorkerData *getWork(Synchroniser *synchroniser) {
    DBGPRINTF("getWork\n");
    WorkerData *ret;

    ret = synchroniser->pDataListHead;
    synchroniser->pDataListHead = ret->next;
    if(synchroniser->pDataListTail == ret) synchroniser->pDataListTail = NULL;

    if(--(synchroniser->listSize) == 0) {
        synchroniser->signal.bWork = 0;
    }

    return ret;
}

static inline void *synchroniserWork(void *pData) {
    DBGPRINTF("synchroniser starting work\n");

    Synchroniser *self = (Synchroniser *)pData;

    pthread_mutex_lock(&(self->mSignal));
    while(1) {
        DBGPRINTF("synchroniser waiting for work\n");
        pthread_cond_wait(&(self->cSignal), &(self->mSignal));
        DBGPRINTF("synchroniser got work to do\n");

        if(self->signal.bWork) {

            do {
                WorkerData *work = getWork(self);

                while(1) {
                    Worker *worker;
                    uint8_t workerFree = 0;
                    for(worker = self->conf->workersListHead; worker != NULL && !workerFree; worker = worker->next) {
                        DBGPRINTF("checking if worker %ld is available\n", worker->tid);
                        workerFree = !pthread_mutex_trylock(&(worker->mSignal));
                        if(workerFree)  break;
                    }
                    pthread_mutex_unlock(&(self->mSignal));

                    if(workerFree) {
                        DBGPRINTF("worker %ld is available\n", worker->tid);
                        worker->pData = work->pData;
                        free(work);
                        worker->signal.bWork |= 1;
                        pthread_cond_signal(&(worker->cSignal));
                        pthread_mutex_unlock(&(worker->mSignal));
                        break;
                    }
                    else {
                        usleep(5000);
                    }
                }
                pthread_mutex_lock(&(self->mSignal));
            } while(self->signal.bWork && !self->signal.bClose);
        }

        if(self->signal.bClose) {
            DBGPRINTF("closing synchroniser\n");
            Worker *worker = self->conf->workersListHead;
            Worker *delete;
            while(worker) {
                delete = worker;
                worker = worker->next;
                if(removeWorkerFromConf(delete, self->conf) != 0) {
                    DBGPRINTF("error while trying to terminate worker\n");
                }
            }
            break;
        }
    }

    pthread_mutex_unlock(&(self->mSignal));
    pthread_exit(0);
}

int workersStartSynchroniser(WorkersCnf *conf) {
    DBGPRINTF("workersStartSynchroniser\n");
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    DBGPRINTF("starting synchroniser\n");
    if(pthread_create(&(conf->sync->thread), &attr, synchroniserWork, (void *)conf->sync) != 0) {
        DBGPRINTF("failed to start synchroniser\n");
        pthread_attr_destroy(&attr);
        pthread_mutex_destroy(&(conf->sync->mSignal));
        pthread_cond_destroy(&(conf->sync->cSignal));
        free(conf->sync);
        return -1;
    }

    DBGPRINTF("synchroniser started successfully\n");
    pthread_attr_destroy(&attr);
    return 0;
}

int workersInitConfig(WorkersCnf *conf) {
    DBGPRINTF("workersInitConfig\n");

    conf->maxWorkers = DEFAULT_MAX_WORKERS;

    DBGPRINTF("creating synchroniser\n");
    Synchroniser *newSync = malloc(sizeof(Synchroniser));
    newSync->conf = conf;
    newSync->pDataListHead = NULL;
    newSync->pDataListTail = NULL;
    newSync->listSize = 0;
    newSync->signal.bClose = 0;
    newSync->signal.bWork = 0;
    pthread_mutex_init(&(newSync->mSignal), NULL);
    pthread_cond_init(&(newSync->cSignal), NULL);

    conf->sync = newSync;
    return 0;
}

void workersDeleteConfig(WorkersCnf *conf) {
    DBGPRINTF("workersDeleteConfig\n");

    DBGPRINTF("locking synchroniser mutex\n");
    pthread_mutex_lock(&(conf->sync->mSignal));

    DBGPRINTF("sending close signal\n");
    conf->sync->signal.bClose = 1;
    pthread_cond_signal(&(conf->sync->cSignal));
    pthread_mutex_unlock(&(conf->sync->mSignal));

    DBGPRINTF("waiting to join thread\n");
    pthread_join(conf->sync->thread, NULL);

    DBGPRINTF("thread joined, destroying/freeing the rest\n");
    pthread_mutex_destroy(&(conf->sync->mSignal));
    pthread_cond_destroy(&(conf->sync->cSignal));
    free(conf->sync);
    free(conf);
}

void workerPing(void *pData) {
    DBGPRINTF("workerPing\n");
    sleep(2);
    return;
}