/* data_pool.h
 *
 * This file contains structures and prototypes of functions used
 * for data pools, used to manage memory inside the program.
 *
 * File begun on 2019-21-06
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


#ifndef DATA_POOL_H
#define DATA_POOL_H

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include "rsyslog.h"

typedef struct DataObject_ {
    void *pObject;
    uint32_t size;

    struct DataPool_ *pool;

    enum {
        EMPTY,
        INIT,
        AVAILABLE,
        USED
    } state;

    uint8_t stale;

    pthread_mutex_t mutex;

    struct DataObject_ *prev;
    struct DataObject_ *next;
} DataObject;

typedef struct DataPool_ {
    char poolName[50];

    struct DataObject_ *head;
    struct DataObject_ *tail;
    uint32_t listSize;
    uint32_t availableElems;
    uint32_t minAvailableElems;
    uint32_t totalAllocSize;

    void* (*objectConstructor)(void *);
    void (*objectDestructor)(void *);
    void (*objectResetor)(void *);

    struct PoolStorage_ *poolStorage;

    pthread_mutex_t mutex;

    struct DataPool_ *prev;
    struct DataPool_ *next;
} DataPool;

typedef struct PoolStorage_ {
    struct DataPool_ *head;
    struct DataPool_ *tail;
    uint8_t listSize;
    uint32_t totalDataSize;
    uint32_t maxDataSize;

    pthread_mutex_t mutex;
} PoolStorage;

#define DEFAULT_MAX_POOL_STORAGE_SIZE   1024
extern PoolStorage *poolStorage;

uint32_t deleteDataObjectFromPool(DataObject *, DataPool *);
void setObjectAvailable(DataObject *);
void updateDataObjectSize(DataObject *, int);
DataObject *getOrCreateAvailableObject(DataPool *);
DataPool *createPool(char*, void* (*objectConstructor(void *)), void (*objectDestructor(void *)),
        void (*objectResetor(void *)), uint32_t);
void destroyPool(DataPool *);
PoolStorage *initPoolStorage();
void deletePoolStorage(PoolStorage *);

#endif /* DATA_POOL_H */
