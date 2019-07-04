/* mmcapture.c
 *
 * This is a parser intended to work in coordination with impcap.
 * This module gets data from the impcap module, and follow TCP streams
 * to capture relevant data (such as files) from packets.
 *
 * File begun on 2018-12-5
 *
 * Created by:
 *  - François Bernard (francois.bernard@isen.yncrea.fr)
 *  - Théo Bertin (theo.bertin@isen.yncrea.fr)
 *  - Tianyu Geng (tianyu.geng@isen.yncrea.fr)
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

#include "config.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <json.h>
#include <sys/types.h>

#include "rsyslog.h"
#include "errmsg.h"
#include "unicode-helper.h"
#include "module-template.h"
#include "rainerscript.h"
#include "rsconf.h"
#include "datetime.h"

#include "packets.h"
#include "file_utils.h"
#include "tcp_sessions.h"
#include "flow.h"
#include "tcp_sessions.h"
#include "yara_utils.h"
#include "workers.h"
#include "data_pool.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmcapture")

/* static data */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(datetime)

#define IMPCAP_METADATA "!impcap"
#define IMPCAP_DATA     "!data"

#define YARA_METADATA   "!yara"

/* conf structures */

typedef struct instanceData_s {
    StreamsCnf *globalStreamsCnf;
    FlowCnf *globalFlowCnf;
    YaraCnf *globalYaraCnf;
    WorkersCnf *workersCnf;
    FileStruct *logFile;
    Worker *memoryManager;

    DataPool *workerDataContextPool;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
    rsconf_t *pConf;
};

static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

/* input instance parameters */
static struct cnfparamdescr actpdescr[] = {
    { "streamStoreFolder", eCmdHdlrString, 0 },
    { "maxConnections", eCmdHdlrPositiveInt, 0 },
    { "yaraRuleFile", eCmdHdlrString, 0 },
    { "yaraScanType", eCmdHdlrGetWord, 0 },
    { "yaraScanMaxSize", eCmdHdlrPositiveInt, 0 },
    { "logFile", eCmdHdlrString, 0 },
    { "threadsNumber", eCmdHdlrPositiveInt, 0 },
    { "maxMemoryUsage", eCmdHdlrPositiveInt, 0 }
};

static struct cnfparamblk actpblk = {
    CNFPARAMBLK_VERSION,
    sizeof(actpdescr)/sizeof(struct cnfparamdescr),
    actpdescr
};

/* --- workers context --- */
typedef struct WorkerDataContext_ {
    smsg_t *pMsg;
    instanceData *instanceData;
    DataObject *object;

} WorkerDataContext;

void *createWorkerDataContext(void *object) {
    DBGPRINTF("createWorkerDataContext\n");
    DataObject *dObject = (DataObject *)object;

    WorkerDataContext *context = calloc(1, sizeof(WorkerDataContext));
    if(context) {
        context->object = dObject;
        dObject->pObject = (void *)context;
        return (void *)sizeof(WorkerDataContext);
    }
    return (void *)0;
}

void destroyWorkerDataContext(void *wdc) {
    DBGPRINTF("destroyWorkerDataContext\n");
    if(wdc) free(wdc);
    return;
}

void resetWorkerDataContext(void *wdcObject) {
    DBGPRINTF("resetWorkerDataContext\n");

    if(wdcObject) {
        WorkerDataContext *wdc = (WorkerDataContext *)wdcObject;
        if(wdc->pMsg) msgDestruct(&(wdc->pMsg));
    }
    return;
}

void *workerDoWork(void *pData) {
    WorkerDataContext *context = (WorkerDataContext *)pData;
    int tcpStatus;

    Packet *pkt = getImpcapData(context->pMsg);
    msgDestruct(&(context->pMsg));
    context->pMsg = NULL;

    pkt->enterTime = datetime.GetTime(NULL);

    pkt->hash = calculatePacketFlowHash(pkt);

//    printPacketInfo(pkt);

    if(pkt->flags & PKT_HASH_READY && context->instanceData->globalYaraCnf->scanType == SCAN_STREAM) {
        pkt->flow = getOrCreateFlowFromHash(pkt);

        if(pkt->flow && pkt->proto == IPPROTO_TCP) {
            pthread_mutex_lock(&(pkt->flow->mFlow));
            tcpStatus = handleTcpFromPacket(pkt);
            pthread_mutex_unlock(&(pkt->flow->mFlow));

//            if(tcpStatus == 1) {
//                /* session is now closed */
//                TcpSession *session = (TcpSession *) pkt->flow->protoCtx;
//                tcpSessionDelete(session);
//                pkt->flow->protoCtx = NULL;
//            }
        }
    }

    if(pkt->payloadLen) {
        struct json_object *yaraMeta = NULL;

        if(context->instanceData->globalYaraCnf->scanType == SCAN_STREAM &&
           pkt->flow && pkt->proto == IPPROTO_TCP && tcpStatus != -1) {
            StreamBuffer *sb;
            pthread_mutex_lock(&(pkt->flow->mFlow));
            TcpSession *session = (TcpSession *)pkt->flow->protoCtx;
            if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
                sb = session->cCon->streamBuffer;
            }
            else {
                sb = session->sCon->streamBuffer;
            }
            pthread_mutex_unlock(&(pkt->flow->mFlow));

            yaraMeta = yaraScan(pkt->payload, pkt->payloadLen, sb);
        }
        else if(context->instanceData->globalYaraCnf->scanType == SCAN_PACKET_ONLY ||
                tcpStatus == -1){
            yaraMeta = yaraScan(pkt->payload, pkt->payloadLen, NULL);
        }

        if(yaraMeta) {
            if(context->instanceData->logFile->pFile) {
                struct fjson_object *jsonLine = fjson_object_new_object();
                struct syslogTime detectionTime;
                char detectionTimeStr[64];
                datetime.getCurrTime(&detectionTime, NULL, 1);
                datetime.formatTimestamp3339(&detectionTime, detectionTimeStr);
                fjson_object_object_add(jsonLine, "ID", fjson_object_new_int(pkt->pktNumber));
                fjson_object_object_add(jsonLine, "time_detected", fjson_object_new_string(detectionTimeStr));
                fjson_object_object_add(jsonLine, "net_src_ip", fjson_object_new_string(getAddrString(pkt->src)));
                fjson_object_object_add(jsonLine, "net_dst_ip", fjson_object_new_string(getAddrString(pkt->dst)));
                fjson_object_object_add(jsonLine, "net_src_port", fjson_object_new_int(pkt->sp));
                fjson_object_object_add(jsonLine, "net_dst_port", fjson_object_new_int(pkt->dp));


                fjson_object_object_add(jsonLine, "yara_match", yaraMeta);

                appendLineToFile(fjson_object_to_json_string(jsonLine), context->instanceData->logFile);
                fjson_object_put(jsonLine);
            }
            else {
                DBGPRINTF("could not write yara rule match to file: no file defined\n");
            }
        }
    }

    pthread_mutex_lock(&(context->object->mutex));
    context->object->state = AVAILABLE;
    pthread_mutex_unlock(&(context->object->mutex));
    freePacket(pkt);

    return NULL;
}

/* --- memory manager --- */
typedef struct MemManagerParams_ {
    Worker *self;
    instanceData *instData;
} MemManagerParams;

void *memoryManagerDoWork(void *pData) {
    MemManagerParams *params = (MemManagerParams *)pData;
    DBGPRINTF("memory manager started\n");

    struct timespec waitTime;

    while(1) {
        clock_gettime(CLOCK_REALTIME, &waitTime);
        waitTime.tv_sec += 10;

        pthread_mutex_lock(&(params->self->conf->mSignal));
        pthread_cond_timedwait(&(params->self->conf->cSignal), &(params->self->conf->mSignal), &waitTime);

        if(params->self->sigStop) {
            DBGPRINTF("memory manager closing\n");
            pthread_mutex_unlock(&(params->self->conf->mSignal));
            pthread_exit(0);
        }

        DBGPRINTF("memory manager launching cleanup\n");
        DataPool *pool;
        for(pool = poolStorage->tail; pool != NULL; pool = pool->next) {
            pthread_mutex_lock(&(pool->mutex));
            uint32_t freeAmount = 0, usedAmount = 0;
            DataObject *object = pool->tail, *delete;
            while(object) {
                delete = object;
                object = object->next;
                pthread_mutex_lock(&(delete->mutex));

                if(delete->state != USED) freeAmount++;
                else usedAmount++;

                if(delete->state != USED && delete->stale &&
                    pool->listSize > params->instData->workersCnf->maxWorkers) {
                    deleteDataObjectFromPool(delete, pool);
                    DBGPRINTF("memory manager deleting object in '%s', "
                              "new listSize: %u\n", pool->poolName, pool->listSize);
                    continue;
                }
                else if(!delete->stale){
                    delete->stale = 1;
                }
                pthread_mutex_unlock(&(delete->mutex));
            }
            pthread_mutex_unlock(&(pool->mutex));
            DBGPRINTF("memory manager: %u free, %u used in '%s', "
                      "for %u total memory\n", freeAmount, usedAmount, pool->poolName, pool->totalAllocSize);
        }

        DBGPRINTF("memory manager cleanup finished, total memory used: %u\n", poolStorage->totalDataSize);
        pthread_mutex_unlock(&(params->self->conf->mSignal));
    }
}

Worker *initMemoryManager() {
    Worker *worker = malloc(sizeof(Worker));
    WorkersCnf *conf = malloc(sizeof(WorkersCnf));
    if(!worker || !conf) {
        DBGPRINTF("could not create worker and conf for memory manager, "
                  "memory allocation failed\n");
        return NULL;
    }

    conf->workFunction = memoryManagerDoWork;
    conf->maxWorkers = 1;
    conf->workersListHead = worker;
    conf->workersNumber = 1;
    pthread_mutex_init(&(conf->mSignal), NULL);
    pthread_cond_init(&(conf->cSignal), NULL);

    worker->sigStop = 0;
    worker->conf = conf;

    return worker;
}

void startMemoryManager(Worker *memManager, instanceData *instData) {
    if(memManager) {
        MemManagerParams *params = malloc(sizeof(MemManagerParams));
        params->self = memManager;
        params->instData = instData;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

        if(pthread_create(&(memManager->thread), &attr, memoryManagerDoWork, (void *)params) != 0) {
            memManager->thread = NULL;
            pthread_attr_destroy(&attr);
            return -1;
        }

        pthread_attr_destroy(&attr);
        return 0;
    }
    else {
        DBGPRINTF("cannot start memory manager: object given is not initialised\n");
    }
    return -1;
}

/* init instance, set parameters */

BEGINbeginCnfLoad
    DBGPRINTF("entering beginCnfLoad\n");
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
    DBGPRINTF("entering endCnfLoad\n");
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
    DBGPRINTF("entering checkCnf\n");
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
    DBGPRINTF("entering activateCnf\n");
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
    DBGPRINTF("entering freeCnf\n");
CODESTARTfreeCnf
ENDfreeCnf

/* create instances */

BEGINcreateInstance
    DBGPRINTF("entering createInstance\n");
CODESTARTcreateInstance
    poolStorage = initPoolStorage();
    pData->globalStreamsCnf = calloc(1, sizeof(StreamsCnf));
    pData->globalFlowCnf = calloc(1, sizeof(FlowCnf));
    pData->globalYaraCnf = calloc(1, sizeof(YaraCnf));
    pData->workersCnf = calloc(1, sizeof(WorkersCnf));
    pData->logFile = createFileStruct();
    pData->workerDataContextPool = createPool("workerDataContextPool", createWorkerDataContext, destroyWorkerDataContext, resetWorkerDataContext);
    initTCPPools();
    pData->memoryManager = initMemoryManager();
ENDcreateInstance

BEGINcreateWrkrInstance
    DBGPRINTF("entering createWrkrInstance\n");
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINfreeInstance
    DBGPRINTF("entering freeInstance\n");
CODESTARTfreeInstance
    workersDeleteConfig(pData->workersCnf);
    streamDeleteConfig(pData->globalStreamsCnf);
    flowDeleteConfig(pData->globalFlowCnf);
    yaraDeleteConfig(pData->globalYaraCnf);
    deleteFileStruct(pData->logFile);
    destroyPool(pData->workerDataContextPool);
    destroyTCPPools();
    deletePoolStorage(poolStorage);
ENDfreeInstance

BEGINfreeWrkrInstance
    DBGPRINTF("entering freeWrkrInstance\n");
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance

BEGINnewActInst
    DBGPRINTF("entering newActInst\n");
    struct cnfparamvals *pvals;
    uint16_t i;
CODESTARTnewActInst
    if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

CODE_STD_STRING_REQUESTnewActInst(1)
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
    CHKiRet(createInstance(&pData));

    flowInitConfig(pData->globalFlowCnf);
    yaraInitConfig(pData->globalYaraCnf);
    streamInitConfig(pData->globalStreamsCnf);
    if(workersInitConfig(pData->workersCnf)) {
        ABORT_FINALIZE(RS_RET_MODULE_LOAD_ERR_INIT_FAILED);
    }
    pData->workersCnf->workFunction = workerDoWork;

    for(i = 0; i < actpblk.nParams; ++i) {
        if(!pvals[i].bUsed)
            continue;

        else if(!strcmp(actpblk.descr[i].name, "maxConnections")) {
            pData->globalFlowCnf->maxFlow = (uint32_t) pvals[i].val.d.n;
            DBGPRINTF("maxConnections set to %u\n", globalFlowCnf->maxFlow);
        }
        else if(!strcmp(actpblk.descr[i].name, "yaraRuleFile")) {
            char *yaraRuleFilename = es_str2cstr(pvals[i].val.d.estr, NULL);
            DBGPRINTF("adding file '%s' to yara compilation\n", yaraRuleFilename);
            FILE *yaraRuleFile = fopen(yaraRuleFilename, "r");

            if(yaraRuleFile) {
                yaraAddRuleFile(yaraRuleFile, NULL, yaraRuleFilename);
                fclose(yaraRuleFile);
                free(yaraRuleFilename);

                if(yaraCompileRules()) {
                    DBGPRINTF("error while compiling yara rules\n");
                    ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
                }
                else {
                    DBGPRINTF("yara rules compiled and ready\n");
                }
            }
        }
        else if(!strcmp(actpblk.descr[i].name, "yaraScanType")) {
            char *scanType = es_str2cstr(pvals[i].val.d.estr, NULL);

            if(strcmp(scanType, "packet") == 0) {
                pData->globalYaraCnf->scanType = SCAN_PACKET_ONLY;
                DBGPRINTF("set yaraScanType to 'packet'\n");
            }
            else if(strcmp(scanType, "stream") == 0) {
                pData->globalYaraCnf->scanType = SCAN_STREAM;
                DBGPRINTF("set yaraScanType to 'stream'\n");
            }
            else {
                free(scanType);
                LogError(0, RS_RET_PARAM_ERROR, "mmcapture: unhandled parameter '%s'\n"
                "valid YARA scan types are 'packet' and 'stream'", actpblk.descr[i].name);
                ABORT_FINALIZE(RS_RET_ERR);
            }
            free(scanType);
        }
        else if(!strcmp(actpblk.descr[i].name, "yaraScanMaxSize")) {
            pData->globalYaraCnf->scanMaxSize = (uint32_t) pvals[i].val.d.n;
            pData->globalStreamsCnf->streamMaxBufferSize = pData->globalYaraCnf->scanMaxSize;
            DBGPRINTF("yaraScanMaxSize set to %u\n", pData->globalYaraCnf->scanMaxSize);
        }
        else if(!strcmp(actpblk.descr[i].name, "streamStoreFolder")) {
            pData->globalStreamsCnf->streamStoreFolder = es_str2cstr(pvals[i].val.d.estr, NULL);

            DBGPRINTF("streamStoreFolder set to '%s'\n", pData->globalStreamsCnf->streamStoreFolder);
        }
        else if(!strcmp(actpblk.descr[i].name, "logFile")) {
            char *fileFullPath = es_str2cstr(pvals[i].val.d.estr, NULL);
            strncpy(pData->logFile->filename, basename(fileFullPath), 256);
            strncpy(pData->logFile->directory, dirname(fileFullPath), 2048);
            free(fileFullPath);
            DBGPRINTF("logFile directory: %s\n", pData->logFile->directory);
            DBGPRINTF("logFile filename: %s\n", pData->logFile->filename);
            FILE *logFile = openFile(pData->logFile->directory, pData->logFile->filename);
            if(logFile) {
                pData->logFile->pFile = logFile;
                fclose(pData->logFile->pFile);
            }
        }
        else if(!strcmp(actpblk.descr[i].name, "threadsNumber")) {
            pData->workersCnf->maxWorkers = (uint8_t) pvals[i].val.d.n;
            if(pData->workersCnf->maxWorkers > 50) {
                pData->workersCnf->maxWorkers = 50;
                LogError(0, RS_RET_INVALID_VALUE, "mmcapture: thread limit is too high -> capped to 50\n");
            }
            DBGPRINTF("threads number set to %u\n", pData->workersCnf->maxWorkers);
        }
        else if(!strcmp(actpblk.descr[i].name, "maxMemoryUsage")) {
            poolStorage->maxDataSize = (uint32_t) pvals[i].val.d.n * 1024 * 1024;
            DBGPRINTF("max memory usage set to %uMB\n", (uint32_t)poolStorage->maxDataSize/1024/1024);
        }
        else {
            LogError(0, RS_RET_PARAM_ERROR, "mmcapture: unhandled parameter '%s'\n", actpblk.descr[i].name);
        }
    }

    if(pData->globalStreamsCnf->streamStoreFolder) {
        if(createFolder(pData->globalStreamsCnf->streamStoreFolder) != 0){
            LogError(0, RS_RET_CONFIG_ERROR, "error while creating folder '%s' for stream dumps,"
            " streams won't be dumped", pData->globalStreamsCnf->streamStoreFolder);
            free(pData->globalStreamsCnf->streamStoreFolder);
            pData->globalStreamsCnf->streamStoreFolder = NULL;
        }
    }


CODE_STD_FINALIZERnewActInst
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

/* runtime functions */

BEGINdoAction_NoStrings
    DBGPRINTF("entering doAction\n");
    smsg_t **ppMsg = (smsg_t **)pMsgData;
    smsg_t *pMsg = *ppMsg;
    int ret;
    instanceData *pData;
CODESTARTdoAction
    pData = pWrkrData->pData;

    if(pData->workersCnf->workersNumber == 0) {
        DBGPRINTF("launching workers\n");
        pData->logFile->pFile = openFile(pData->logFile->directory, pData->logFile->filename);

        uint8_t thread;
        for(thread = 0; thread < pData->workersCnf->maxWorkers; thread++) {
            addWorkerToConf(pData->workersCnf);
        }

        startMemoryManager(pData->memoryManager, pData);
    }

    DataObject *wdcObject = getOrCreateAvailableObject(pData->workerDataContextPool);
    WorkerDataContext *context;
    if(wdcObject) {
        context = wdcObject->pObject;
    }
    else {
        DBGPRINTF("WARNING: could not get object to handle new msg, dropping\n");
        return 0;
    }

    context->pMsg = MsgAddRef(pMsg);
    context->instanceData = pData;

    DataObject *wdObject = getOrCreateAvailableObject(pData->workersCnf->workerDataPool);
    WorkerData *work;
    if(wdObject) {
        work = wdObject->pObject;
    }
    else {
        msgDestruct(&(context->pMsg));
        context->pMsg = NULL;
        pthread_mutex_lock(&(context->object->mutex));
        context->object->state = AVAILABLE;
        pthread_mutex_unlock(&(context->object->mutex));
        DBGPRINTF("WARNING: could not get object to handle new msg, dropping\n");
        return 0;
    }

    work->pData = (void *)context;
    work->next = NULL;
    addWork(work, pData->workersCnf);

ENDdoAction

BEGINparseSelectorAct
    DBGPRINTF("entering parseSelectorAct\n");
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

BEGINtryResume
    DBGPRINTF("entering tryResume\n");
CODESTARTtryResume
ENDtryResume

BEGINisCompatibleWithFeature
    DBGPRINTF("entering isCompatibleWithFeature\n");
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature

BEGINdbgPrintInstInfo
    DBGPRINTF("entering dbgPrintInstInfo\n");
CODESTARTdbgPrintInstInfo
	DBGPRINTF("mmcapture\n");
ENDdbgPrintInstInfo

BEGINmodExit
CODESTARTmodExit
    DBGPRINTF("mmcapture: exit\n");
    objRelease(datetime, CORE_COMPONENT);
ENDmodExit

/* declaration of functions */

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
    DBGPRINTF("mmcapture: init\n");
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    CHKiRet(objUse(datetime, CORE_COMPONENT));
ENDmodInit
