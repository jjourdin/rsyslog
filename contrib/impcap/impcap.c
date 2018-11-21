/* impcap.c
 *
 * This is a first implementation of an input module using libpcap, a
 * portable C/C++ library for network traffic capture.
 * This module aims to read packets received from a network interface
 * using libpcap to extract information, such as IP addresses, ports,
 * protocols, etc... and make it available to rsyslog and its modules.
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
 #include <pcap.h>

 #include "rsyslog.h"
 #include "errmsg.h"
 #include "unicode-helper.h"
 #include "module-template.h"
 #include "rainerscript.h"
 #include "rsconf.h"
 #include "dirty.h"
 #include "msg.h"


MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("impcap")

/* static data */
DEF_IMOD_STATIC_DATA

static rsRetVal resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal);
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_RARP 0x8035
/* network structures protocols*/
struct eth_header_s {
  uint8_t destMac[6];
  uint8_t srcMac[6];
  uint16_t ethType;
};

struct IPv4_header_s {
	uint8_t		version:4;
	uint8_t 	IHL:4;
	uint8_t 	DSCP_ECN;
	uint16_t 	totalLen;
	uint16_t 	id;
	uint16_t 	fragSegment;
	uint8_t 	TTL;
	uint8_t 	protocol;
	uint16_t 	checksum;
	uint8_t 	srcIP[4];
	uint8_t 	dstIP[4];
};

struct IPv6_header_s {
	uint8_t 	version:4;
	uint8_t		trafficClass;
	uint32_t 	flowLabel:20;
	uint16_t	payloadLen;
	uint8_t		nextHeader;
	uint8_t		hopLimit;
	uint16_t	srcAddr[8];
	uint16_t	dstAddr[8];
};

struct TCP_header_s {
	uint16_t	srcPort;
	uint16_t	dstport;
	uint32_t	seqNO;
	uint32_t	ackNO;
};

struct arp_header_s {
	uint16_t hType; /*hardware type*/
	uint16_t pType; /*protocol type*/
	uint8_t hAddrLen; /*hardware address length */
	uint8_t pAddrLen; /*protocol address length*/
	uint16_t operation; /*operation*/
};

/* conf structures */

struct instanceConf_s {
  uchar *interface;
  pcap_t *device;
  struct instanceConf_s *next;
};

struct modConfData_s {
  rsconf_t *pConf;
  instanceConf_t *root, *tail;
  uint16_t snap_length;
};

static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
	{ "interface", eCmdHdlrString, CNFPARAM_REQUIRED }
};
static struct cnfparamblk inppblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(inppdescr)/sizeof(struct cnfparamdescr),
	  inppdescr
	};

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "snap_length", eCmdHdlrPositiveInt, 0 }
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};

/* --- prototypes --- */
void handle_packet(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet);
void run();
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
  inst->interface = NULL;
  inst->device = NULL;

	/* node created, let's add to global config */
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

/* input instances */

BEGINnewInpInst
  struct cnfparamvals *pvals;
  instanceConf_t *inst;
  int i;
CODESTARTnewInpInst
  pvals = nvlstGetParams(lst, &inppblk, NULL);

  if(pvals == NULL) {
    LogError(0, RS_RET_MISSING_CNFPARAMS,
              "impcap: required parameter are missing\n");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  CHKiRet(createInstance(&inst));

  for(i = 0 ; i < inppblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(inppblk.descr[i].name, "interface")) {
      inst->interface = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else {
      dbgprintf("impcap: non-handled param %s in beginCnfLoad\n", inppblk.descr[i].name);
    }
  }

finalize_it:
CODE_STD_FINALIZERnewInpInst
  cnfparamvalsDestruct(pvals, &inppblk);
ENDnewInpInst

/* global mod conf (v2 system) */

BEGINsetModCnf
  struct cnfparamvals *pvals = NULL;
  int i;
CODESTARTsetModCnf
  pvals = nvlstGetParams(lst, &modpblk, NULL);

  for(i = 0 ; i < modpblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(modpblk.descr[i].name, "snap_length")) {
      loadModConf->snap_length = (int) pvals[i].val.d.n;
    }
    else {
      dbgprintf("impcap: non-handled param %s in beginCnfLoad\n", modpblk.descr[i].name);
    }
  }
ENDsetModCnf

/* config v2 system */

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
  loadModConf = pModConf;
  loadModConf->pConf = pConf;
  loadModConf->snap_length = 65535;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
  instanceConf_t *inst;
CODESTARTcheckCnf
  if(pModConf->root == NULL) {
    LogError(0, RS_RET_NO_LISTNERS , "impcap: module loaded, but "
        "no interface defined - no input will be gathered");
    iRet = RS_RET_NO_LISTNERS;
  }

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    if(inst->interface == NULL || !strcmp((char *)inst->interface, "")) {
      iRet = RS_RET_INVALID_PARAMS;
      LogError(0, RS_RET_LOAD_ERROR, "impcap: interface parameter "
          "invalid: %s", inst->interface);
      break;
    }
  }
ENDcheckCnf

BEGINactivateCnfPrePrivDrop
CODESTARTactivateCnfPrePrivDrop
ENDactivateCnfPrePrivDrop

BEGINactivateCnf
  instanceConf_t *inst;
  pcap_t *dev;
  char errBuf[PCAP_ERRBUF_SIZE];
CODESTARTactivateCnf
  loadModConf = pModConf;

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    dev = pcap_open_live((const char *)inst->interface, loadModConf->snap_length, 0, 0, errBuf);
    if(dev == NULL) {
      LogError(0, RS_RET_LOAD_ERROR, "impcap: error while opening interface using pcap");
      ABORT_FINALIZE(RS_RET_LOAD_ERROR);
    }
    inst->device = dev;
  }

finalize_it:
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf

/* runtime functions */

BEGINrunInput
  instanceConf_t *inst;
  int id = 0;
CODESTARTrunInput
inst = loadModConf->root; /* only start first instance for now */
  pcap_loop(inst->device, -1, handle_packet, (uchar *)&id);
ENDrunInput

BEGINwillRun
CODESTARTwillRun
ENDwillRun

BEGINafterRun
  instanceConf_t *inst;
CODESTARTafterRun
  for(inst = loadModConf->root ; inst != NULL; inst = inst->next) {
    pcap_close(inst->device);
  }
ENDafterRun

BEGINmodExit
CODESTARTmodExit
ENDmodExit

/* declaration of functions */

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES /* might need it */
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION;
ENDmodInit


/* ---message handling functions --- */

/* callback for packet received from pcap_loop */
void handle_packet(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet) {
  smsg_t *pMsg;
  DEFiRet;

  msgConstruct(&pMsg);
  MsgSetRawMsg(pMsg, "impcap packet", 14);

  submitMsg2(pMsg);

finalize_it:
  return;
}
void handle_ethhead(const uchar *packet,smsg_t *pMsg)
{
	struct eth_header_s* eth = (struct eth_header_s*)(packet);
	char macString[20];
	snprintf(macString, 18,"%X:%X:%X:%X:%X:%X",
                	(eth->destMac)[0],
                	(eth->destMac)[1],
                	(eth->destMac)[2],
                	(eth->destMac)[3],
                	(eth->destMac)[4],
                	(eth->destMac)[5]);
	MsgAddMetadata(pMsg, "destination Mac", macString);
	snprintf(macString, 18,"%X:%X:%X:%X:%X:%X",
                	(eth->srcMac)[0],
                	(eth->srcMac)[1],
                	(eth->srcMac)[2],
                	(eth->srcMac)[3],
                	(eth->srcMac)[4],
                	(eth->srcMac)[5]);
	MsgAddMetadata(pMsg, "source Mac", macString);
	MsgAddMetadata(pMsg, "ethernet type", eth->ethType);
	next_type = eth->ethtype;
	if(next_type==ETH_TYPE_IPV4):
		handle_ipv4head((*packet+sizeof(struct eth_header_s)),*pMsg);
	else if(next_type==ETH_TYPE_IPV6):
		handle_ipv6head((*packet+sizeof(struct eth_header_s)),*pMsg);
	else if(next_type==ETH_TYPE_ARP):
		handle_arphead((*packet+sizeof(struct eth_header_s)),*pMsg);

}

void handle_ipv4head(const uchar *packet,smsg_t *pMsg)
{
	ipv4 = (struct IPv4_header_s*)(packet);
	MsgAddMetadata(pMsg, "Internet Header Length", ipv4->IHL);
	MsgAddMetadata(pMsg, "Length of entire IP Packet", ipv4->totalLen);
	MsgAddMetadata(pMsg, "Protocol", ipv4->protocol);
	char ipString[20];
	snprintf(ipString, 16,"%X,%X,%X,%X",
                	(ipv4->srcIP)[0],
                	(ipv4->srcIP)[1],
                	(ipv4->srcIP)[2],
                	(ipv4->srcIP)[3]);
	MsgAddMetadata(pMsg, "source IP", ipString);
	snprintf(ipString, 16,"%X,%X,%X,%X",
                	(ipv4->dstIP)[0],
                	(ipv4->dstIP)[1],
                	(ipv4->dstIP)[2],
                	(ipv4->dstIP)[3]);
	MsgAddMetadata(pMsg, "destination IP", ipString);
}

void handle_ipv6head(const uchar *packet,smsg_t *pMsg)
{
	ipv6 = (struct IPv6_header_s*)(packet);
	MsgAddMetadata(pMsg, "IPv6 trafficClass", ipv6->trafficClass);
	MsgAddMetadata(pMsg, "IPv6 flowLabel", ipv6->flowLabel);
	MsgAddMetadata(pMsg, "IPv6 Payload Length", ipv6->payloadLen);
	MsgAddMetadata(pMsg, "IPv6 Next Header", ipv6->nextHeader);
	char addressString[50]
	snprintf(addressString, 40,"%X:%X:%X:%X:%X:%X:%X:%X",
                	(ipv6->srcAddr)[0],
                	(ipv6->srcAddr)[1],
                	(ipv6->srcAddr)[2],
                	(ipv6->srcAddr)[3],
			(ipv6->srcAddr)[4],
                	(ipv6->srcAddr)[5],
                	(ipv6->srcAddr)[6],
                	(ipv6->srcAddr)[7]);
	MsgAddMetadata(pMsg, "source address", addressString);
	snprintf(addressString, 40,"%X:%X:%X:%X:%X:%X:%X:%X",
                	(ipv6->dstAddr)[0],
                	(ipv6->dstAddr)[1],
                	(ipv6->dstAddr)[2],
                	(ipv6->dstAddr)[3],
			(ipv6->dstAddr)[4],
                	(ipv6->dstAddr)[5],
                	(ipv6->dstAddr)[6],
                	(ipv6->dstAddr)[7]);
	MsgAddMetadata(pMsg, "destination address", addressString);
}

void handle_arphead(const uchar *packet,smsg_t *pMsg)
{
	arp = (struct arp_header_s*)(packet);
	MsgAddMetadata(pMsg, "protocol type", arp->pType);
	MsgAddMetadata(pMsg, "operation", arp->operation);
}
