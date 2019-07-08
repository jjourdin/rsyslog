/* data_pool.c
 *
 * This file contains functions used for memory management.
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
#include "data_pool.h"

PoolStorage *poolStorage;

static inline DataObject *createDataObject(DataPool *pool) {
    DBGPRINTF("createDataObject\n");

    DataObject *newDataObject = malloc(sizeof(DataObject));
    if(newDataObject) {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

        newDataObject->pObject = NULL;
        newDataObject->state = INIT;
        newDataObject->stale = 1;
        pthread_mutex_init(&(newDataObject->mutex), &attr);
        newDataObject->pool = pool;
        newDataObject->size = sizeof(DataObject);

        pthread_mutexattr_destroy(&attr);
        return newDataObject;
    }

    DBGPRINTF("ERROR: could not create new Data Object\n");
    return NULL;
}

static inline void addObjectToPool(DataPool *pool, DataObject *object) {
    DBGPRINTF("addObjectToPool\n");

    pthread_mutex_lock(&(pool->mutex));

    if(pool->head) {
        object->prev = pool->head;
        pool->head->next = object;
    }
    pool->head = object;
    object->next = NULL;
    pool->listSize++;
    if(!pool->tail) pool->tail = object;

    pthread_mutex_unlock(&(pool->mutex));

    return;
}

static inline void addPoolToStorage(DataPool *pool) {
    DBGPRINTF("addPoolToStorage\n");

    if(poolStorage->head) {
        pool->prev = poolStorage->head;
        poolStorage->head->next = pool;
    }
    poolStorage->head = pool;
    pool->next = NULL;
    poolStorage->listSize++;
    if(!poolStorage->tail) poolStorage->tail = pool;

    pool->poolStorage = poolStorage;

    return;
}

uint32_t deleteDataObjectFromPool(DataObject *object, DataPool *pool) {
    DBGPRINTF("deleteDataObjectFromPool\n");
    uint32_t dataFreed = 0;

    if(pool && object && object->state != USED) {

        pthread_mutex_lock(&(pool->mutex));

        if(object->next) object->next->prev = object->prev;
        if(object->prev) object->prev->next = object->next;
        if(pool->head == object) pool->head = object->prev;
        if(pool->tail == object) pool->tail = object->next;
        pool->listSize--;
        pool->totalAllocSize -= object->size;
        dataFreed = object->size;

        pthread_mutex_lock(&(pool->poolStorage->mutex));
        pool->poolStorage->totalDataSize -= object->size;
        pthread_mutex_unlock(&(pool->poolStorage->mutex));

        pthread_mutex_unlock(&(pool->mutex));


        pool->objectDestructor(object->pObject);
        pthread_mutex_destroy(&(object->mutex));
        free(object);
    }
    return dataFreed;
}

void setObjectAvailable(DataObject *object) {
    DBGPRINTF("setObjectAvailable\n");
    pthread_mutex_lock(&(object->mutex));
    object->state = AVAILABLE;
    object->pool->objectResetor(object->pObject);
    pthread_mutex_unlock(&(object->mutex));
}

void updateDataObjectSize(DataObject *object, int diffSize) {
    if(object) {
        pthread_mutex_lock(&(object->mutex));
        object->size += diffSize;
        pthread_mutex_unlock(&(object->mutex));

        pthread_mutex_lock(&(object->pool->mutex));
        object->pool->totalAllocSize += diffSize;
        pthread_mutex_unlock(&(object->pool->mutex));

        pthread_mutex_lock(&(object->pool->poolStorage->mutex));
        object->pool->poolStorage->totalDataSize += diffSize;
        pthread_mutex_unlock(&(object->pool->poolStorage->mutex));
    }
    return;
}

DataObject *getOrCreateAvailableObject(DataPool *pool) {
    DBGPRINTF("getOrCreateAvailableObject in pool '%s', current number of objects: %d\n", pool->poolName, pool->listSize);

    pthread_mutex_lock(&(pool->mutex));

    DataObject *object = pool->tail;
    while(object) {
        pthread_mutex_lock(&(object->mutex));
        if(object->state == AVAILABLE) {
            pthread_mutex_unlock(&(object->mutex));
            break;
        }
        pthread_mutex_unlock(&(object->mutex));
        object = object->next;
    }

    if(!object) {
        if(poolStorage->totalDataSize >= poolStorage->maxDataSize) {
            DBGPRINTF("WARNING: max memory usage reached, cannot create new objects\n");
            pthread_mutex_unlock(&(pool->mutex));
            return NULL;
        }

        DBGPRINTF("getOrCreateAvailableObject in pool '%s', no free object, creating new\n", pool->poolName);
        object = createDataObject(pool);
        uint32_t sizeAlloc = (uint32_t)pool->objectConstructor((void *)object);

        if(sizeAlloc > 0) {
            object->size += sizeAlloc;
            addObjectToPool(pool, object);
            object->pool->totalAllocSize += object->size;
            object->pool->poolStorage->totalDataSize += object->size;
        }
        else {
            pthread_mutex_destroy(&(object->mutex));
            free(object);
            pthread_mutex_unlock(&(pool->mutex));
            return NULL;
        }
        DBGPRINTF("getOrCreateAvailableObject in pool '%s', new pool size: %u\n", pool->poolName, pool->listSize);
    }

    object->state = USED;
    object->stale = 0;

    pthread_mutex_unlock(&(pool->mutex));

    return object;
}

DataPool *createPool(char *poolName, void* (*objectConstructor(void *)), void (*objectDestructor(void *)), void (*objectResetor(void *))) {
    DBGPRINTF("createPool\n");

    DataPool *newPool = malloc(sizeof(DataPool));
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    if(newPool) {
        strncpy(newPool->poolName, poolName, 50);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        if(pthread_mutex_init(&(newPool->mutex), &attr) != 0) {
            DBGPRINTF("ERROR: could not initialize mutex while creating new pool\n");
            return NULL;
        }
        newPool->head = NULL;
        newPool->tail = NULL;
        newPool->listSize = 0;
        newPool->objectConstructor = objectConstructor;
        newPool->objectDestructor = objectDestructor;
        newPool->objectResetor = objectResetor;
        newPool->totalAllocSize = sizeof(DataPool);
    }
    else {
        DBGPRINTF("ERROR: could not create new pool\n");
    }
    pthread_mutexattr_destroy(&attr);

    addPoolToStorage(newPool);
    return newPool;
}

void destroyPool(DataPool *pool) {
    DBGPRINTF("destroyPool\n");

    pthread_mutex_lock(&(pool->mutex));

    DataObject *object = pool->tail, *destroy;
    while(object != NULL) {
        destroy = object;
        object = object->next;
        pthread_mutex_destroy(&(destroy->mutex));
        if(destroy->pObject) pool->objectDestructor(destroy->pObject);
        free(destroy);
    }

    pthread_mutex_unlock(&(pool->mutex));
    pthread_mutex_destroy(&(pool->mutex));
    free(pool);

    return;
}

PoolStorage *initPoolStorage() {
    PoolStorage *poolStorage = malloc(sizeof(PoolStorage));

    if(poolStorage) {
        poolStorage->head = NULL;
        poolStorage->tail = NULL;
        poolStorage->listSize = 0;
        poolStorage->totalDataSize = 0;
        poolStorage->maxDataSize = DEFAULT_MAX_POOL_STORAGE_SIZE;
        pthread_mutex_init(&(poolStorage->mutex), NULL);
        return poolStorage;

    }

    DBGPRINTF("ERROR: could not initialize pool storage\n");
    return NULL;
}

void deletePoolStorage(PoolStorage *poolStorage) {
    if(poolStorage) {
        pthread_mutex_destroy(&(poolStorage->mutex));
        free(poolStorage);
    }
    return;
}