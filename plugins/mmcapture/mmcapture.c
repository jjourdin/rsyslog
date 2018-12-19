/* mmcapture.c
 *
 * This is a parser intended to work in coordination with impcap.
 * This module gets data from the impcap module, and follow streams
 * to capture relevant data, such as files, from packets.
 *
 * File begun on 2018-11-13
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

#include "file_utils.h"
#include "tcp_sessions.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmcapture")

/* static data */
DEF_OMOD_STATIC_DATA

#define IMPCAP_METADATA "!impcap"
#define IMPCAP_DATA     "!data"

static char* proto_list[] = {
  "http",
  "ftp",
  "smb"
};

/* conf structures */

typedef struct instanceData_s {
  uchar* protocol;
  uchar* folder;
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
	{ "protocol", eCmdHdlrString, 0 },
  { "folder", eCmdHdlrString, 0 }
};
static struct cnfparamblk actpblk =
{ CNFPARAMBLK_VERSION,
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
  pData->protocol = NULL;
  pData->folder = "/var/log/rsyslog/";
ENDcreateInstance

BEGINcreateWrkrInstance
DBGPRINTF("entering createWrkrInstance\n");
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINfreeInstance
DBGPRINTF("entering freeInstance\n");
CODESTARTfreeInstance
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

  for(i = 0; i < actpblk.nParams; ++i) {
    if(!pvals[i].bUsed)
      continue;

    if(!strcmp(actpblk.descr[i].name, "protocol")) {
      pData->protocol = es_str2cstr(pvals[i].val.d.estr, NULL);
      DBGPRINTF("protocol set to '%s'", pData->protocol);
    }
    else if(!strcmp(actpblk.descr[i].name, "folder")) {
      pData->folder = es_str2cstr(pvals[i].val.d.estr, NULL);
      DBGPRINTF("folder set to '%s'", pData->folder);

    }
    else {
      LogError(0, RS_RET_PARAM_ERROR, "mmcapture: unhandled parameter '%s'", actpblk.descr[i].name);
    }
  }

  if(createFolder(pData->folder)){
    ABORT_FINALIZE(RS_RET_ERR);
  }
CODE_STD_FINALIZERnewActInst
ENDnewActInst

/* runtime functions */

rsRetVal getImpcapTCPMetadata(smsg_t *pMsg, tcp_packet *data) {
  rsRetVal iRet;
  struct json_object *pJson = NULL;
  msgPropDescr_t *pDesc = malloc(sizeof(msgPropDescr_t));

  DBGPRINTF("entered getImpcapTCPMetadata\n");

  msgPropDescrFill(pDesc, (uchar*)IMPCAP_METADATA, strlen(IMPCAP_METADATA));
  iRet = msgGetJSONPropJSON(pMsg, pDesc, &pJson);

  if(iRet == 0) {
    struct json_object *obj = NULL;
    char *flags_str;
    int i;

    if(fjson_object_object_get_ex(pJson, "IP_proto", &obj)) {
      if(fjson_object_get_int(obj) == TCP_PROTO) {
        if(data->meta == NULL)
          data->meta = malloc(sizeof(tcp_metadata));

        if(fjson_object_object_get_ex(pJson, "net_src_port", &obj)) {
          data->meta->srcPort = fjson_object_get_int(obj);
          DBGPRINTF("source_port: %u\n", data->meta->srcPort);
        }

        if(fjson_object_object_get_ex(pJson, "net_dst_port", &obj)) {
          data->meta->dstPort = fjson_object_get_int(obj);
          DBGPRINTF("dest_port: %u\n", data->meta->dstPort);
        }

        if(fjson_object_object_get_ex(pJson, "TCP_seq_number", &obj)) {
          data->meta->seqNum = fjson_object_get_int64(obj);
          DBGPRINTF("seq_number: %lu\n", data->meta->seqNum);
        }

        if(fjson_object_object_get_ex(pJson, "TCP_ack_number", &obj)) {
          data->meta->ackNum = fjson_object_get_int64(obj);
          DBGPRINTF("ack_number: %lu\n", data->meta->ackNum);
        }

        if(fjson_object_object_get_ex(pJson, "net_flags", &obj)) {
          data->meta->flags = fjson_object_get_string(obj);
          DBGPRINTF("flags: %s\n", data->meta->flags);
        }
      }
    }
  }

  msgPropDescrDestruct(pDesc);
  return iRet;
}

BEGINdoAction_NoStrings
DBGPRINTF("entering doAction\n");
  smsg_t **ppMsg = (smsg_t **)pMsgData;
  smsg_t *pMsg = *ppMsg;
CODESTARTdoAction
  struct tcp_packet *parsed_data = malloc(sizeof(tcp_packet));

  iRet = getImpcapTCPMetadata(pMsg, parsed_data);
  DBGPRINTF("return value: %d\n", iRet);

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
ENDmodInit
