/* imhiredis.c
* Copyright 2021 aDvens
*
* This file is contrib for rsyslog.
* This input plugin is a log consumer from REDIS
* See README for doc
*
*
* This program is free software: you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation, either version 3 of
* the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this program. If not, see
* <http://www.gnu.org/licenses/>.
*
* Author: Jérémie Jourdin
* <jeremie.jourdin@advens.fr>
*/

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/uio.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>

#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "atomic.h"
#include "statsobj.h"
#include "unicode-helper.h"
#include "prop.h"
#include "ruleset.h"
#include "glbl.h"
#include "cfsysline.h"
#include "msg.h"
#include "dirty.h"

MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("imhiredis")

/* static data */
DEF_IMOD_STATIC_DATA
#define QUEUE_BATCH_SIZE 1000
#define IMHIREDIS_MODE_QUEUE 1
#define IMHIREDIS_MODE_SUBSCRIBE 2
DEFobjCurrIf(prop)
DEFobjCurrIf(ruleset)
DEFobjCurrIf(glbl)
DEFobjCurrIf(statsobj)

/* forward references */
static void * imhirediswrkr(void *myself);


/* Module static data */
static struct configSettings_s {
	uchar *server; /* redis server address */
	int port; /* redis port */
	uchar *password; /* redis password */
	uchar *modeDescription; /* mode description */
	int mode; /* mode constant */
	uchar *key; /* key for QUEUE and PUBLISH modes */
	sbool useLPop; /* Should we use RPUSH instead of RPOP? */ 

	uchar *pszBindRuleset;
} cs;

struct instanceConf_s {
	uchar *server;
	int port;
	uchar *password;
	uchar *key;
	uchar *modeDescription;
	int mode;
	sbool useLPop;
	ruleset_t *pBindRuleset;	/* ruleset to bind listener to (use system default if unspecified) */
	uchar *pszBindRuleset;		/* default name of Ruleset to bind to */
	int bIsConnected;
	redisContext *conn;
        redisAsyncContext *aconn;

	struct instanceConf_s *next;
};


struct modConfData_s {
	rsconf_t *pConf;		/* our overall config object */
	uchar *server;
	int port;
	uchar *password;
	uchar *key;
	int mode;
	sbool useLPop;
	instanceConf_t *root, *tail;
	ruleset_t *pBindRuleset;	/* ruleset to bind listener to (use system default if unspecified) */
	uchar *pszBindRuleset;		/* default name of Ruleset to bind to */
};

/* global data */
pthread_attr_t wrkrThrdAttr;	/* Attribute for worker threads ; read only after startup */
static int activeHiredisworkers = 0;
/* The following structure controls the worker threads. Global data is
 * needed for their access.
 */
static struct imhiredisWrkrInfo_s {
	pthread_t tid;		/* the worker's thread ID */
	instanceConf_t *inst;	/* Pointer to imhiredis instance */
} *imhiredisWrkrInfo;

static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current load process */

static prop_t *pInputName = NULL;
/* there is only one global inputName for all messages generated by this input */

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "ruleset", eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
	{ "server", eCmdHdlrGetWord, 0 },
	{ "port", eCmdHdlrInt, 0 },
	{ "password", eCmdHdlrGetWord, 0 },
	{ "mode", eCmdHdlrGetWord, 0 },
	{ "key", eCmdHdlrGetWord, 0 },
	{ "uselpop", eCmdHdlrInt, 0 },
	{ "ruleset", eCmdHdlrString, 0 },
};
static struct cnfparamblk inppblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(inppdescr)/sizeof(struct cnfparamdescr),
	  inppdescr
	};

struct timeval redis_connect_timeout = { 1, 500000 }; /* 1.5 seconds */


#include "im-helper.h" /* must be included AFTER the type definitions! */

/* ------------------------------ callbacks ------------------------------ */




/* ------------------------------ end callbacks ------------------------------ */


/* enqueue the hiredis message. The provided string is
 * not freed - thuis must be done by the caller.
 */
static rsRetVal enqMsg(instanceConf_t *const __restrict__ inst, const char *message)
{
	DEFiRet;
	smsg_t *pMsg;

	if (message != NULL && message[0] == '\0') {
		/* we do not process empty lines */
		FINALIZE;
	}

	DBGPRINTF("imkhiredis: enqMsg: Msg: %s\n", message);

	CHKiRet(msgConstruct(&pMsg));
	MsgSetInputName(pMsg, pInputName);
	MsgSetRawMsg(pMsg, message, strlen(message));
	MsgSetFlowControlType(pMsg, eFLOWCTL_LIGHT_DELAY);
	MsgSetRuleset(pMsg, inst->pBindRuleset);
	MsgSetMSGoffs(pMsg, 0);	/* we do not have a header... */
	CHKiRet(submitMsg2(pMsg));

finalize_it:
	RETiRet;
}


/**
 * Asynchronous subscribe callback handler
 */
static void msgSubscribeAsync (redisAsyncContext * c, void *reply, instanceConf_t *const __restrict__ inst) {
	/* 
		redisReply is supposed to be an array of three elements: [''message', <channel>, <message>]


		JJO: For future reference (https://github.com/redis/hiredis/blob/master/README.md)

		Important: the current version of hiredis (1.0.0) frees replies when the asynchronous API is used. 
		This means you should not call freeReplyObject when you use this API. 
		The reply is cleaned up by hiredis after the callback returns. 
		We may introduce a flag to make this configurable in future versions of the library.
	*/

  	redisReply * r = reply;
  	if (r == NULL) return ;

	if (r->element[2]->str == NULL) {
		return;
	}
	enqMsg(inst, r->element[2]->str);
}



/* create input instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal
createInstance(instanceConf_t **pinst)
{
	instanceConf_t *inst;
	DEFiRet;
	CHKmalloc(inst = malloc(sizeof(instanceConf_t)));
	inst->next = NULL;
	inst->server = NULL;
	inst->port = 0;
	inst->password = NULL;
	inst->key = NULL;
	inst->mode = 0;
	inst->useLPop = 0;
	inst->pszBindRuleset = NULL;
	inst->pBindRuleset = NULL;
	inst->bIsConnected = 0;
	/* Redis objects */
	inst->conn = NULL;
	inst->aconn = NULL;

	/* node created, let's add to config */
	if(loadModConf->tail == NULL) {
		loadModConf->tail = loadModConf->root = inst;
	} else {
		loadModConf->tail->next = inst;
		loadModConf->tail = inst;
	}

	*pinst = inst;
finalize_it:
	RETiRet;
}

/* this function checks instance parameters and does some required pre-processing
 */
static rsRetVal ATTR_NONNULL()
checkInstance(instanceConf_t *const inst)
{
	DEFiRet;
	
	redisReply *reply=NULL;

	/* establish our connection to redis */
	if (inst->server != NULL) {
		DBGPRINTF("imhiredis: setting server: '%s'\n", inst->server);
	}
	else {
		LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: error: no server defined !");
		ABORT_FINALIZE(RS_RET_HIREDIS_ERROR);
	}
	if (inst->port != 0) {
		DBGPRINTF("imhiredis: setting port: '%d'\n", inst->port);
	}
	else {
		LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: error: no port defined !");
		ABORT_FINALIZE(RS_RET_HIREDIS_ERROR);
	}
	if (inst->key != NULL) {
		DBGPRINTF("imhiredis: setting key/channel: '%s'\n", inst->key);
	}
	else {
		LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: error: no key defined !");
		ABORT_FINALIZE(RS_RET_HIREDIS_ERROR);
	}

	DBGPRINTF("imhiredis: trying connect to '%s' at port %d\n", inst->server, inst->port);
	inst->bIsConnected = 0;

	if (inst->mode == IMHIREDIS_MODE_SUBSCRIBE) 
	{
		DBGPRINTF("imhiredis: setting mode: 'SUBSCRIBE'\n");
		inst->aconn = redisAsyncConnect((const char *)inst->server, inst->port);

		//In case of an error, don't abort here because it is handled later, within the thread
		if (inst->aconn->err) {
			LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: can not initialize redis handle");
			//ABORT_FINALIZE(RS_RET_HIREDIS_ERROR);
		}
		// Redis Consumer is opened 
		inst->bIsConnected = 1;
	} 
	else if (inst->mode == IMHIREDIS_MODE_QUEUE) {
		DBGPRINTF("imhiredis: setting mode: 'QUEUE'\n");
		inst->conn = redisConnectWithTimeout((const char *)inst->server, inst->port, redis_connect_timeout);

		// In case of an error, don't abort because it is handled later, within the thread 
		if (inst->conn->err) {
			LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: can not initialize redis handle");
			//ABORT_FINALIZE(RS_RET_HIREDIS_ERROR);
		}
		// Redis Consumer is opened 
		inst->bIsConnected = 1;
	}
	else {
		DBGPRINTF("imhiredis: invalid mode, please choose 'subscribe' or 'queue' mode  \n");
		LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: can not initialize redis handle");
		ABORT_FINALIZE(RS_RET_HIREDIS_ERROR);
	}

	if (inst->password != NULL) {
		DBGPRINTF("imhiredis: setting password: '%s'\n", inst->password);
	}


finalize_it:
	if (reply != NULL)
		freeReplyObject(reply);
	RETiRet;
}

/* function to generate an error message if the ruleset cannot be found */
static inline void
std_checkRuleset_genErrMsg(__attribute__((unused)) modConfData_t *modConf, instanceConf_t *inst)
{
	LogError(0, NO_ERRCODE, "imhiredis: ruleset '%s' not found - "
		"using default ruleset instead",
		inst->pszBindRuleset);
}


BEGINnewInpInst
	struct cnfparamvals *pvals;
	instanceConf_t *inst;
	int i;
CODESTARTnewInpInst
	DBGPRINTF("newInpInst (imhiredis)\n");

	if((pvals = nvlstGetParams(lst, &inppblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("input param blk in imhiredis:\n");
		cnfparamsPrint(&inppblk, pvals);
	}

	CHKiRet(createInstance(&inst));
	for(i = 0 ; i < inppblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;

		if(!strcmp(inppblk.descr[i].name, "server")) {
			inst->server = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "port")) {
			inst->port = (int) pvals[i].val.d.n;
		} else if(!strcmp(inppblk.descr[i].name, "password")) {
			inst->password = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(inppblk.descr[i].name, "uselpop")) {
			inst->useLPop = pvals[i].val.d.n;
		} else if(!strcmp(inppblk.descr[i].name, "mode")) {
			inst->modeDescription = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
			if (!strcmp((const char*)inst->modeDescription, "queue")) {
				inst->mode = IMHIREDIS_MODE_QUEUE;
			} else if (!strcmp((const char*)inst->modeDescription, "subscribe")) {
				inst->mode = IMHIREDIS_MODE_SUBSCRIBE;
			} else {
				dbgprintf("imhiredis: unsupported mode %s\n", inppblk.descr[i].name);
			}
		} else if(!strcmp(inppblk.descr[i].name, "key")) {
			inst->key = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("imhiredis: program error, non-handled "
				"param '%s'\n", inppblk.descr[i].name);
		}
	}

	DBGPRINTF("imhiredis: checking config sanity\n");


	if (inst->modeDescription == NULL) {
		CHKmalloc(inst->modeDescription = (uchar*)strdup("subscribe"));
		inst->mode = IMHIREDIS_MODE_SUBSCRIBE;
		LogMsg(0, NO_ERRCODE, LOG_INFO, "imhiredis: \"mode\" parameter not specified "
			"using default redis 'subscribe' mode -- this may not be what you want!");
		DBGPRINTF("imhiredis: \"mode\" parameter not specified "
                        "using default redis 'subscribe' mode -- this may not be what you want!");
	}
	if (inst->key == NULL) {
		CHKmalloc(inst->key = (uchar*)strdup("vulture"));
		LogMsg(0, NO_ERRCODE, LOG_INFO, "imhiredis: \"key\" parameter not specified "
			"using default 'vulture' key -- this may not be what you want!");
		DBGPRINTF("imhiredis: \"key\" parameter not specified "
			"using default 'vulture' key -- this may not be what you want!");
	}
	if(inst->server == NULL) {
		CHKmalloc(inst->server = (uchar *)strdup("127.0.0.1"));
		LogMsg(0, NO_ERRCODE, LOG_INFO, "imhiredis: \"server\" parameter not specified "
			"using default of 127.0.0.1 -- this may not be what you want!");
		DBGPRINTF("imhiredis: \"server\" parameter not specified "
			"using default of 127.0.0.1 -- this may not be what you want!");
	}
	if (inst->password == NULL) {
		LogMsg(0, NO_ERRCODE, LOG_INFO, "imhiredis: Warning: no password specified ");
		DBGPRINTF("imhiredis: Warning: no password specified ");
	}

	DBGPRINTF("imhiredis: newInpIns server=%s, port=%d, key=%s, mode=%s, uselpop=%d\n",
		inst->server, inst->port, inst->key, inst->modeDescription, inst->useLPop);

finalize_it:
CODE_STD_FINALIZERnewInpInst
	cnfparamvalsDestruct(pvals, &inppblk);
ENDnewInpInst


BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
	pModConf->pszBindRuleset = NULL;
ENDbeginCnfLoad


BEGINsetModCnf
	struct cnfparamvals *pvals = NULL;
	int i;
CODESTARTsetModCnf
	pvals = nvlstGetParams(lst, &modpblk, NULL);
	if(pvals == NULL) {
		LogError(0, RS_RET_MISSING_CNFPARAMS, "imhiredis: error processing module "
			"config parameters [module(...)]");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	if(Debug) {
		dbgprintf("module (global) param blk for imhiredis:\n");
		cnfparamsPrint(&modpblk, pvals);
	}

	for(i = 0 ; i < modpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(modpblk.descr[i].name, "ruleset")) {
			loadModConf->pszBindRuleset = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("imhiredis: program error, non-handled "
			  "param '%s' in beginCnfLoad\n", modpblk.descr[i].name);
		}
	}
finalize_it:
	if(pvals != NULL)
		cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

BEGINendCnfLoad
CODESTARTendCnfLoad
	if(loadModConf->pszBindRuleset == NULL) {
		if((cs.pszBindRuleset == NULL) || (cs.pszBindRuleset[0] == '\0')) {
			loadModConf->pszBindRuleset = NULL;
		} else {
			CHKmalloc(loadModConf->pszBindRuleset = ustrdup(cs.pszBindRuleset));
		}
	}
finalize_it:
	free(cs.pszBindRuleset);
	cs.pszBindRuleset = NULL;
	loadModConf = NULL; /* done loading */
ENDendCnfLoad

BEGINcheckCnf
	instanceConf_t *inst;
CODESTARTcheckCnf
	for(inst = pModConf->root ; inst != NULL ; inst = inst->next) {
		if(inst->pszBindRuleset == NULL && pModConf->pszBindRuleset != NULL) {
			CHKmalloc(inst->pszBindRuleset = ustrdup(pModConf->pszBindRuleset));
		}
		std_checkRuleset(pModConf, inst);
	}
finalize_it:
ENDcheckCnf


BEGINactivateCnfPrePrivDrop
CODESTARTactivateCnfPrePrivDrop
	runModConf = pModConf;
ENDactivateCnfPrePrivDrop

BEGINactivateCnf
CODESTARTactivateCnf
	for(instanceConf_t *inst = pModConf->root ; inst != NULL ; inst = inst->next) {
		iRet = checkInstance(inst);
	}
ENDactivateCnf


BEGINfreeCnf
	instanceConf_t *inst, *del;
CODESTARTfreeCnf
	for(inst = pModConf->root ; inst != NULL ; ) {
		free(inst->server);
		if (inst->password != NULL)
			free(inst->password);
		free(inst->modeDescription);
		free(inst->key);
		free(inst->pszBindRuleset);
		del = inst;
		inst = inst->next;
		free(del);
	}
	free(pModConf->pszBindRuleset);
ENDfreeCnf


/* Cleanup imhiredis worker threads */
static void
shutdownImhiredisWorkers(void)
{
	int i;
	instanceConf_t *inst;

	assert(imhiredisWrkrInfo != NULL);

	DBGPRINTF("imhiredis: waiting on imhiredis workerthread termination\n");
	for(i = 0 ; i < activeHiredisworkers ; ++i) {
		pthread_join(imhiredisWrkrInfo[i].tid, NULL);
		DBGPRINTF("imhiredis: Stopped worker %d\n", i);
	}
	free(imhiredisWrkrInfo);
	imhiredisWrkrInfo = NULL;

	for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
		DBGPRINTF("imhiredis: stop consuming %s:%d/%s\n",
			inst->server, inst->port, inst->key);
		if(inst->conn != NULL) {
                	redisFree(inst->conn);
                	inst->conn = NULL;
        	}
		if(inst->aconn != NULL) {
                	redisAsyncFree(inst->aconn);
                	inst->aconn = NULL;
        	}
		DBGPRINTF("imhiredis: stopped consuming %s:%d/%s\n",
			inst->server, inst->port, inst->key);
	}
}


/* This function is called to gather input.  */
BEGINrunInput
	int i;
	instanceConf_t *inst;
CODESTARTrunInput
	DBGPRINTF("imhiredis: runInput loop started ...\n");
	activeHiredisworkers = 0;
	for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
		if(inst->conn != NULL) {
			++activeHiredisworkers;
		}
		else if(inst->aconn != NULL) {
			++activeHiredisworkers;
		}
	}

	if(activeHiredisworkers == 0) {
		LogError(0, RS_RET_ERR, "imhiredis: no active inputs, input does "
			"not run - there should have been additional error "
			"messages given previously");
		ABORT_FINALIZE(RS_RET_ERR);
	}


	DBGPRINTF("imhiredis: Starting %d imhiredis workerthreads\n", activeHiredisworkers);
	imhiredisWrkrInfo = calloc(activeHiredisworkers, sizeof(struct imhiredisWrkrInfo_s));
	if (imhiredisWrkrInfo == NULL) {
		LogError(errno, RS_RET_OUT_OF_MEMORY, "imhiredis: worker-info array allocation failed.");
		ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
	}

	/* Start worker threads for each imhiredis input source
	*/
	i = 0;
	for(inst = runModConf->root ; inst != NULL ; inst = inst->next) {
		/* init worker info structure! */
		imhiredisWrkrInfo[i].inst = inst; /* Set reference pointer */
		pthread_create(&imhiredisWrkrInfo[i].tid, &wrkrThrdAttr, imhirediswrkr, &(imhiredisWrkrInfo[i]));
		i++;
	}

	while(glbl.GetGlobalInputTermState() == 0) {

		/* Note: the additional 10000ns wait is vitally important. It guards rsyslog
		 * against totally hogging the CPU if the users selects a polling interval
		 * of 0 seconds. It doesn't hurt any other valid scenario. So do not remove.
		 */
		if(glbl.GetGlobalInputTermState() == 0)
			srSleep(0, 100000);
	}
	DBGPRINTF("imhiredis: terminating upon request of rsyslog core\n");

	/* we need to shutdown hiredis worker threads here because this operation can
	 * potentially block (e.g. when no hiredis server is available!). If this
	 * happens in runInput, the rsyslog core can cancel our thread. However,
	 * in afterRun this is not possible, because the core does not assume it
	 * can block there. -- rgerhards, 2018-10-23
	 */
	shutdownImhiredisWorkers();
finalize_it:
ENDrunInput


BEGINwillRun
CODESTARTwillRun
	/* we need to create the inputName property (only once during our lifetime) */
	CHKiRet(prop.Construct(&pInputName));
	CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imhiredis"), sizeof("imhiredis") - 1));
	CHKiRet(prop.ConstructFinalize(pInputName));
finalize_it:
ENDwillRun


BEGINafterRun
CODESTARTafterRun
	if(pInputName != NULL)
		prop.Destruct(&pInputName);

ENDafterRun


BEGINmodExit
CODESTARTmodExit
	pthread_attr_destroy(&wrkrThrdAttr);
	/* release objects we used */
	objRelease(statsobj, CORE_COMPONENT);
	objRelease(ruleset, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
	objRelease(prop, CORE_COMPONENT);
ENDmodExit


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURENonCancelInputTermination)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES
CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
	/* request objects we use */
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(prop, CORE_COMPONENT));
	CHKiRet(objUse(ruleset, CORE_COMPONENT));
	CHKiRet(objUse(statsobj, CORE_COMPONENT));

	/* initialize "read-only" thread attributes */
	pthread_attr_init(&wrkrThrdAttr);
	pthread_attr_setstacksize(&wrkrThrdAttr, 4096*1024);

ENDmodInit

/*
 *	Workerthread function for a single hiredis consomer
 */
static void *
imhirediswrkr(void *myself)
{
	struct imhiredisWrkrInfo_s *me = (struct imhiredisWrkrInfo_s*) myself;
	int rc, i;
	DBGPRINTF("imhiredis: started hiredis consumer workerthread on %s:%d/%s\n",
		me->inst->server, me->inst->port, me->inst->key);

	do {
		if(glbl.GetGlobalInputTermState() == 1)
			break; /* terminate input! */

		/* Handle Redis reconnexion */
		if(me->inst->bIsConnected == 0)
		{
			//Sleep 10 seconds before attempting to resume a broken connexion
			srSleep(10, 0);

			DBGPRINTF("imhiredis: Redis problem, attempting to recover...  Working key is '%s' \n", me->inst->key);
			LogError(0, NO_ERRCODE, "imhiredis: Redis problem, attempting to recover... Working key is '%s' \n", me->inst->key);
			if (me->inst->mode == IMHIREDIS_MODE_SUBSCRIBE)
        		{
                		DBGPRINTF("imhiredis: setting mode: 'SUBSCRIBE'\n");
                		me->inst->aconn = redisAsyncConnect((const char *)me->inst->server, me->inst->port);
                		if (me->inst->aconn->err) {
					DBGPRINTF("imhiredis: can not recover redis connexion on server '%s', port '%d' for channel '%s'", me->inst->server, me->inst->port, me->inst->key);
                		        LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: can not recover redis connexion on server '%s', port '%d' for channel '%'", me->inst->server, me->inst->port, me->inst->key);
               			}
				else me->inst->bIsConnected = 1;
        		}
        		else if (me->inst->mode == IMHIREDIS_MODE_QUEUE) {
				DBGPRINTF("imhiredis: setting mode: 'QUEUE'\n");
				me->inst->conn = redisConnectWithTimeout((const char *)me->inst->server, me->inst->port, redis_connect_timeout);
				if (me->inst->conn->err) {
					DBGPRINTF("imhiredis: can not recover redis connexion on server '%s', port '%d' for queue '%s'", me->inst->server, me->inst->port, me->inst->key);
                		        LogError(0, RS_RET_HIREDIS_ERROR, "imhiredis: can not recover redis connexion on server '%s', port '%d' queue key '%'", me->inst->server, me->inst->port, me->inst->key);
				}
				else me->inst->bIsConnected = 1;
			}
		}


		if(me->inst->bIsConnected == 1 && (me->inst->conn != NULL || me->inst->aconn != NULL)) 
		{
			if (me->inst->aconn != NULL && me->inst->mode==IMHIREDIS_MODE_SUBSCRIBE) 
			{
				if (me->inst->password) {
					rc = redisAsyncCommand(me->inst->aconn, NULL, me->inst, "AUTH %s", me->inst->password);
					if (rc != REDIS_OK) {
						LogError(0, NO_ERRCODE, "imhiredis: WARNING: Authentication failure !\n");
						me->inst->bIsConnected = 0;
						//break;
					}
				}
				DBGPRINTF("imhiredis: Subscribing to key %s \n",me->inst->key);
				struct event_base *base = event_base_new();
				redisLibeventAttach(me->inst->aconn, base);
                                redisAsyncCommand(me->inst->aconn, msgSubscribeAsync, me->inst, "SUBSCRIBE %s", me->inst->key);
				event_base_dispatch(base);

				/* We should never be there, except in case of a connexion failure or redis issue */
				DBGPRINTF("imhiredis: WARNING: Connexion lost to REDIS for key '%s' \n", me->inst->key);
                            	LogError(0, NO_ERRCODE, "imhiredis: WARNING: Connexion lost to REDIS for key '%s' \n", me->inst->key);
				me->inst->bIsConnected = 0;

			}
			else if (me->inst->conn != NULL && me->inst->mode==IMHIREDIS_MODE_QUEUE) 
			{
				redisReply *reply=NULL;
				if (me->inst->password) {
					rc = redisAppendCommand(me->inst->conn, "AUTH %s", me->inst->password);
					if (rc != REDIS_OK) {
						LogError(0, NO_ERRCODE, "imhiredis: WARNING: Authentication failure !\n");
						me->inst->bIsConnected = 0;
						//break;
					}
					rc = redisGetReply(me->inst->conn, (void **) &reply);
					if (rc != REDIS_OK) {
                                	        LogError(0, NO_ERRCODE, "imhiredis: Authentication error");
						me->inst->bIsConnected = 0;
						if (reply != NULL) 
							freeReplyObject(reply);
                                	        //break;
                                	}
					if (strcmp(reply->str, "OK")) {
                                	        LogError(0, NO_ERRCODE, "imhiredis: Authentication failure");
						me->inst->bIsConnected = 0;
						if (reply != NULL) 
							freeReplyObject(reply);
                                	        //break;
					}
					
				}
				if (me->inst->useLPop == 1) 
				{ 
					DBGPRINTF("imhiredis: Queuing #%d LPOP commands on key '%s' \n", QUEUE_BATCH_SIZE, me->inst->key);
					for ( i=0; i<QUEUE_BATCH_SIZE; ++i ) {
						redisAppendCommand(me->inst->conn, "LPOP %s", me->inst->key);
					}
				}
				else {
					DBGPRINTF("imhiredis: Queuing #%d RPOP commands on key '%s' \n", QUEUE_BATCH_SIZE, me->inst->key);
					for (i=0; i<QUEUE_BATCH_SIZE; i++) {
						redisAppendCommand(me->inst->conn, "RPOP %s", me->inst->key);
					}
				}
				
				while ( i-- > 0 ) 
				{
					rc = redisGetReply(me->inst->conn, (void **) &reply);
					if (rc != REDIS_OK) 
					{
                                	        LogError(0, NO_ERRCODE, "imhiredis: Error reading reply after POP#%d on key '%s'", i, me->inst->key);
						me->inst->bIsConnected = 0;
						if (reply != NULL) 
							freeReplyObject(reply);
                                	        break;
                                	}
					if (reply->str != NULL) 
						enqMsg(me->inst->conn, reply->str);
					if (reply != NULL) 
						freeReplyObject(reply);
				}
			}
			else {
				DBGPRINTF("imhiredis: ERROR ! No available mode - this should not happen... \n");
				break;
			}
		}

		/* Note: the additional 10000ns wait is vitally important. It guards rsyslog
		 * against totally hogging the CPU if the users selects a polling interval
		 * of 0 seconds. It doesn't hurt any other valid scenario. So do not remove.
		 * rgerhards, 2008-02-14
		 */
		if(glbl.GetGlobalInputTermState() == 0)
			srSleep(0, 100000);
	} while(glbl.GetGlobalInputTermState() == 0);


	DBGPRINTF("imhiredis: stopped hiredis consumer workerthread on %s:%d/%s\n",
		me->inst->server, me->inst->port, me->inst->key);
	return NULL;
}
