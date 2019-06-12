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
            strncpy(pData->logFile->fileFullPath, es_str2cstr(pvals[i].val.d.estr, NULL), 256);
            FILE *logFile = openFile(dirname(pData->logFile->fileFullPath), basename(pData->logFile->fileFullPath));
            if(logFile) {
                pData->logFile->pFile = logFile;
                DBGPRINTF("logFile '%s' opened\n", pData->logFile->fileFullPath);
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

    Packet *pkt = getImpcapData(pMsg);

    pkt->enterTime = datetime.GetTime(NULL);

    pkt->hash = calculatePacketFlowHash(pkt);

//    printPacketInfo(pkt);

    if(pkt->flags & PKT_HASH_READY) {
        pkt->flow = getOrCreateFlowFromHash(pkt);

        if(pkt->flow && pkt->proto == IPPROTO_TCP) {
            ret = handleTcpFromPacket(pkt);

            if(ret == 1) {
                /* session is now closed */
                TcpSession *session = (TcpSession *) pkt->flow->protoCtx;

                tcpSessionDelete(session);
                pkt->flow->protoCtx = NULL;
            }


        }
    }

    if(pkt->payloadLen) {
        struct json_object *yaraMeta = NULL;

        if(pData->globalYaraCnf->scanType == SCAN_STREAM &&
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
        else if(pData->globalYaraCnf->scanType == SCAN_PACKET_ONLY){
            yaraMeta = yaraScan(pkt->payload, pkt->payloadLen, NULL);
        }

        if(yaraMeta) {
            if(pData->logFile->pFile) {
                DBGPRINTF("appening line to file\n");
                appendLineToFile(fjson_object_to_json_string(yaraMeta), pData->logFile);
            }
            else {
                msgAddJSON(pMsg, (unsigned char *)YARA_METADATA, yaraMeta, 0, 0);
            }
        }
    }

    DBGPRINTF("freeing packet\n");
    freePacket(pkt);
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
