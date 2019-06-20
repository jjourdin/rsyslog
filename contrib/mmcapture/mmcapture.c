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
    { "logFile", eCmdHdlrString, 0 }
};

static struct cnfparamblk actpblk = {
    CNFPARAMBLK_VERSION,
    sizeof(actpdescr)/sizeof(struct cnfparamdescr),
    actpdescr
};

/* workers context */
typedef struct WorkerDataContext_ {
    smsg_t *pMsg;
    instanceData *instanceData;

} WorkerDataContext;

void *workerDoWork(void *pData) {
    WorkerDataContext *context = (WorkerDataContext *)pData;
    int ret;

    Packet *pkt = getImpcapData(context->pMsg);
    msgDestruct(&(context->pMsg));

    pkt->enterTime = datetime.GetTime(NULL);

    pkt->hash = calculatePacketFlowHash(pkt);

//    printPacketInfo(pkt);

    if(pkt->flags & PKT_HASH_READY && context->instanceData->globalYaraCnf->scanType == SCAN_STREAM) {
        pkt->flow = getOrCreateFlowFromHash(pkt);

        if(pkt->flow && pkt->proto == IPPROTO_TCP) {
            pthread_mutex_lock(&(pkt->flow->mFlow));
            ret = handleTcpFromPacket(pkt);
            pthread_mutex_unlock(&(pkt->flow->mFlow));

//            if(ret == 1) {
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
           pkt->flow && pkt->proto == IPPROTO_TCP) {
            StreamBuffer *sb;
            TcpSession *session = (TcpSession *)pkt->flow->protoCtx;
            if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
                sb = session->cCon->streamBuffer;
            }
            else {
                sb = session->sCon->streamBuffer;
            }

            yaraMeta = yaraScan(pkt->payload, pkt->payloadLen, sb);
        }
        else if(context->instanceData->globalYaraCnf->scanType == SCAN_PACKET_ONLY){
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
            }
            else {
                DBGPRINTF("could not write yara rule match to file: no file defined\n");
            }
        }
    }

    DBGPRINTF("freeing packet\n");
    freePacket(pkt);

    return NULL;
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
    pData->globalStreamsCnf = calloc(1, sizeof(StreamsCnf));
    pData->globalFlowCnf = calloc(1, sizeof(FlowCnf));
    pData->globalYaraCnf = calloc(1, sizeof(YaraCnf));
    pData->workersCnf = calloc(1, sizeof(WorkersCnf));
    pData->logFile = createFileStruct();
ENDcreateInstance

BEGINcreateWrkrInstance
    DBGPRINTF("entering createWrkrInstance\n");
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINfreeInstance
    DBGPRINTF("entering freeInstance\n");
CODESTARTfreeInstance
    streamDeleteConfig(pData->globalStreamsCnf);
    flowDeleteConfig(pData->globalFlowCnf);
    yaraDeleteConfig(pData->globalYaraCnf);
    workersDeleteConfig(pData->workersCnf);
    deleteFileStruct(pData->logFile);
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
            DBGPRINTF("yaraScanMaxSize set to %u\n", pData->globalYaraCnf->scanMaxSize);
        }
        else if(!strcmp(actpblk.descr[i].name, "streamStoreFolder")) {
            free(pData->globalStreamsCnf->streamStoreFolder); /* freeing old allocated memory */
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
        else {
            LogError(0, RS_RET_PARAM_ERROR, "mmcapture: unhandled parameter '%s'\n", actpblk.descr[i].name);
        }
    }

    if(createFolder(pData->globalStreamsCnf->streamStoreFolder) != 0){
        LogError(0, RS_RET_CONFIG_ERROR, "error while creating folder '%s' for stream dumps,"
                                         " streams won't be dumped", pData->globalStreamsCnf->streamStoreFolder);
        free(pData->globalStreamsCnf->streamStoreFolder);
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
        pData->logFile->pFile = openFile(pData->logFile->directory, pData->logFile->filename);

        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
        addWorkerToConf(pData->workersCnf);
    }

    WorkerDataContext *context = malloc(sizeof(WorkerDataContext));
    context->pMsg = MsgDup(pMsg);
    context->instanceData = pData;

    WorkerData *work = malloc(sizeof(WorkerData));
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
