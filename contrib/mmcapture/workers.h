/* workers.h
 *
 * This file contains structures and prototypes of functions used
 * for thread workers.
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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "rsyslog.h"

#ifndef WORKERS_H
#define WORKERS_H

typedef struct Worker_ {
    pthread_t thread;
    long tid;

    void *pData;
    void (*workFunction)(void *);

    struct {
        uint8_t bClose: 1;
        uint8_t bWork: 1;
    } signal;

    pthread_mutex_t mSignal;
    pthread_cond_t cSignal;

    struct Worker_ *next;
    struct Worker_ *prev;
} Worker;

typedef struct WorkerData_ {
    void *pData;
    struct WorkerData_ *next;
} WorkerData;

typedef struct Synchroniser_ {
    pthread_t thread;

    struct WorkersCnf_ *conf;

    WorkerData *pDataListHead;
    WorkerData *pDataListTail;
    uint16_t listSize;

    struct {
        uint8_t bClose: 1;
        uint8_t bWork: 1;
    } signal;

    pthread_mutex_t mSignal;
    pthread_cond_t cSignal;
} Synchroniser;

typedef struct WorkersCnf_ {
    void (*workFunction)(void *);

    Synchroniser *sync;

    uint8_t maxWorkers;
#define DEFAULT_MAX_WORKERS 10

    Worker *workersListHead;
    uint8_t workersNumber;
} WorkersCnf;

int addWorkerToConf(WorkersCnf *);
int removeWorkerFromConf(Worker *, WorkersCnf *);
void addWork(WorkerData *, Synchroniser *);
int workersInitConfig(WorkersCnf *);
void workersDeleteConfig(WorkersCnf *);
void workerPing(void *);


#endif /* WORKERS_H */
