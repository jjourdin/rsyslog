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

static inline DataObject *createDataObject() {
    DBGPRINTF("createDataObject\n");

    DataObject *newDataObject = malloc(sizeof(DataObject));
    if(newDataObject) {
        newDataObject->pObject = NULL;
        newDataObject->state = INIT;
        newDataObject->stale = 1;
        pthread_mutex_init(&(newDataObject->mutex), NULL);
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
    poolStorage->size++;
    if(!poolStorage->tail) poolStorage->tail = pool;

    return;
}

void deleteDataObjectFromPool(DataObject *object, DataPool *pool) {
    DBGPRINTF("deleteDataObjectFromPool\n");

    if(pool && object && object->state != USED) {
        pthread_mutex_lock(&(pool->mutex));
        if(object->next) object->next->prev = object->prev;
        if(object->prev) object->prev->next = object->next;
        if(pool->head == object) pool->head = object->prev;
        if(pool->tail == object) pool->tail = object->next;
        pool->listSize--;
        pthread_mutex_unlock(&(pool->mutex));

        pool->objectDestructor(object->pObject);
        pthread_mutex_destroy(&(object->mutex));
        free(object);
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
        DBGPRINTF("getOrCreateAvailableObject in pool '%s', no free object, creating new\n", pool->poolName);
        object = createDataObject();
        void *pObject = pool->objectConstructor((void *)object);

        if(pObject) {
            object->pObject = pObject;
            addObjectToPool(pool, object);
        }
        DBGPRINTF("getOrCreateAvailableObject in pool '%s', new pool size: %u\n", pool->poolName, pool->listSize);
    }
    else {
        DBGPRINTF("getOrCreateAvailableObject in pool '%s', found object, resetting\n", pool->poolName);
        pool->objectResetor(object->pObject);
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