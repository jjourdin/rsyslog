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

void addWork(WorkerData *work, WorkersCnf *conf) {
    DBGPRINTF("addWork\n");

    pthread_mutex_lock(&(conf->mSignal));

    if(!conf->pDataListHead)    conf->pDataListHead = work;
    if(conf->pDataListTail)     conf->pDataListTail->next = work;
    conf->pDataListTail = work;
    conf->listSize++;

    pthread_cond_signal(&(conf->cSignal));
    pthread_mutex_unlock(&(conf->mSignal));

    return;
}

/**
 * synchroniser's mutex SHOULD be locked before calling function
 * @param conf
 * @return
 */
static inline WorkerData *getWork(WorkersCnf *conf) {
    DBGPRINTF("getWork\n");
    WorkerData *ret = NULL;

    if(conf->listSize != 0) {
        ret = conf->pDataListHead;
        conf->pDataListHead = ret->next;
        if(conf->pDataListTail == ret) conf->pDataListTail = NULL;
        conf->listSize--;
    }

    return ret;
}

static inline void *workerWaitWork(void *pData) {
    Worker *self = (Worker *)pData;
    DBGPRINTF("workerWaitWork, tid: %ld\n", self->tid);

    while(1) {
        pthread_mutex_lock(&(self->conf->mSignal));
        while(self->conf->listSize == 0 && !self->sigStop) {
            pthread_cond_wait(&(self->conf->cSignal), &(self->conf->mSignal));
        }

        if(self->sigStop) {
            DBGPRINTF("worker [%d] closing\n", self->tid);
            pthread_mutex_unlock(&(self->conf->mSignal));
            pthread_exit(0);
        }

        WorkerData *work = getWork(self->conf);
        pthread_mutex_unlock(&(self->conf->mSignal));

        if(work) {
            DBGPRINTF("WORKER [%ld] got work to do\n", self->tid);
            self->conf->workFunction(work->pData);
            pthread_mutex_lock(&(work->object->mutex));
            work->object->state = AVAILABLE;
            pthread_mutex_unlock(&(work->object->mutex));
        }
    }
}

static inline int stopWorker(Worker *worker) {
    DBGPRINTF("stopWorker, tid: %ld\n", worker->tid);
    void *status;

    pthread_mutex_lock(&(worker->conf->mSignal));
    worker->sigStop = 1;
    pthread_cond_broadcast(&(worker->conf->cSignal));
    pthread_mutex_unlock(&(worker->conf->mSignal));

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
        retWorker = malloc(sizeof(Worker));
        retWorker->tid = conf->workersNumber+1;
        retWorker->pData = NULL;
        retWorker->next = NULL;
        retWorker->prev = NULL;
        retWorker->conf = conf;
        retWorker->sigStop = 0;
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
    free(worker);
}

int addWorkerToConf(WorkersCnf *conf) {
    DBGPRINTF("addWorkerToConf\n");
    Worker *new = createWorker(conf);

    if(new) {
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

static inline void *createWorkerData(void *dObject) {
    DBGPRINTF("createWorkerData\n");

    WorkerData *wd = calloc(1, sizeof(WorkerData));
    if(wd) wd->object = dObject;
    return (void *)wd;
}

static inline void destroyWorkerData(void *wdObject) {
    DBGPRINTF("destroyWorkerData\n");

    if(wdObject) {
        WorkerData *wd = (WorkerData *)wdObject;
        free(wd);
    }
    return;
}

static inline void resetWorkerData(void *wdObject) {
    DBGPRINTF("resetWorkerData\n");

    if(wdObject) {
        WorkerData *wd = (WorkerData *)wdObject;
        wd->pData = NULL;
        wd->next = NULL;
    }
    return;
}

int workersInitConfig(WorkersCnf *conf) {
    DBGPRINTF("workersInitConfig\n");

    conf->maxWorkers = DEFAULT_MAX_WORKERS;

    conf->pDataListHead = NULL;
    conf->pDataListTail = NULL;
    conf->listSize = 0;
    conf->workerDataPool = createPool(createWorkerData, destroyWorkerData, resetWorkerData);
    pthread_mutex_init(&(conf->mSignal), NULL);
    pthread_cond_init(&(conf->cSignal), NULL);

    return 0;
}

void workersDeleteConfig(WorkersCnf *conf) {
    DBGPRINTF("workersDeleteConfig\n");

    Worker *delete, *worker = conf->workersListHead;
    while(worker) {
        delete = worker;
        worker = worker->next;
        removeWorkerFromConf(delete, conf);
    }

    DBGPRINTF("thread joined, destroying/freeing the rest\n");
    destroyPool(conf->workerDataPool);
    pthread_mutex_destroy(&(conf->mSignal));
    pthread_cond_destroy(&(conf->cSignal));
    free(conf);
}
