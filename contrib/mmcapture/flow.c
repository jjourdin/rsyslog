/* flow.c
 *
 * This file contains functions used for flow handling.
 *
 * File begun on 2019-05-15
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

#include "flow.h"

FlowCnf *globalFlowCnf;

static inline Flow *createNewFlow() {
    DBGPRINTF("createNewFlow\n")

    Flow *flow = calloc(1, sizeof(Flow));

    if(flow) {
        CLEAR_ADDR(&flow->src);
        CLEAR_ADDR(&flow->dst);

        if(pthread_mutex_init(&flow->mLock, NULL) != 0) {
            DBGPRINTF("could not init flow mutex\n");
        }
    }
    else {
        DBGPRINTF("error: could not claim memory for new Flow object\n")
    }

    return flow;
}

void deleteFlow(Flow *flow) {
    if(flow) {
        pthread_mutex_destroy(&(flow->mLock));
        if(flow->protoCtx) free(flow->protoCtx);
        free(flow);
    }

    return;
}

static inline FlowList *initNewFlowList() {
    DBGPRINTF("initNewFlowList\n")

    FlowList *flowList = NULL;

    flowList = calloc(1, sizeof(FlowList));
    if(flowList) {
        if(pthread_mutex_init(&(flowList->mLock), NULL) == 0) {
            return flowList;
        }
    }

    return NULL;
}

static inline void deleteFlowListElems(FlowList *flowList) {
    if(flowList) {
        Flow *delete, *flow = flowList->head;
        while(flow) {
            delete = flow;
            flow = flow->nextFlow;
            deleteFlow(delete);
        }

        flowList->listSize = 0;
    }

    return;
}

static inline void deleteFlowList(FlowList *flowList) {
    if(flowList) {
        pthread_mutex_destroy(&(flowList->mLock));
        free(flowList);
    }
    return ;
}

static inline int addFlowToList(Flow *flow, FlowList *flowList) {
    DBGPRINTF("addFlowToList\n")

    if(flow && flowList) {
        pthread_mutex_lock(&flowList->mLock);
        if(flowList->tail) {
            flowList->tail->nextFlow = flow;
            flowList->tail = flow;

            pthread_mutex_lock(&flow->mLock);
            flow->prevFlow = flowList->tail;
            flow->nextFlow = NULL;
            pthread_mutex_unlock(&flow->mLock);
        }
        else {
            flowList->tail = flow;
            flowList->head = flow;
        }
        flowList->listSize++;
        pthread_mutex_unlock(&flowList->mLock);
        return 1;
    }
    else {
        return 0;
    }
}

static inline int removeFlowFromList(Flow *flow, FlowList *flowList) {
    DBGPRINTF("removeFlowFromList\n")

    if(flow && flowList) {
        if(flowList->head) {
            Flow *flowSearch = flowList->head;
            uint8_t found = 0;

            do {
                found = (flow == flowSearch) ? 1 : 0;
            }while(flowSearch->nextFlow && !found);

            if(found) {
                pthread_mutex_lock(&flowList->mLock);
                if (flowSearch->nextFlow) {
                    flowSearch->nextFlow = flowSearch->prevFlow;
                }
                if (flowSearch->prevFlow) {
                    flowSearch->prevFlow = flowSearch->nextFlow;
                }
                if (flowSearch == flowList->head) {
                    flowList->head = flowList->head->nextFlow;
                }
                if (flowSearch == flowList->tail) {
                    flowList->tail = flowList->tail->prevFlow;
                }
                flowList->listSize--;
                pthread_mutex_unlock(&flowList->mLock);

                pthread_mutex_lock(&flow->mLock);
                flow->nextFlow = NULL;
                flow->prevFlow = NULL;
                pthread_mutex_unlock(&flow->mLock);

                return 1;
            }
        }
    }

    return 0;
}

void flowInitConfig(FlowCnf *conf) {
    DBGPRINTF("init flow config, conf addr: %p\n", conf);
    memset(conf, 0, sizeof(FlowCnf));

    conf->hash_rand = (uint32_t) getRandom();
    conf->hash_size = FLOW_DEFAULT_HASHSIZE;
    conf->maxFlow = FLOW_DEFAULT_MAXCONN;

    DBGPRINTF("global flow conf hash_rand: %u\n", conf->hash_rand);
    DBGPRINTF("global flow conf hash_size: %u\n", conf->hash_size);
    DBGPRINTF("global flow conf maxFlow: %u\n", conf->maxFlow);

    conf->flowHashLists = calloc(conf->hash_size, sizeof(FlowList *));
    conf->flowList = initNewFlowList();
    if(!conf->flowList) {
        DBGPRINTF("error: could not create new flowList for global flow configuration\n")
        return;
    }

    globalFlowCnf = conf;
    return;
}

void flowDeleteConfig(FlowCnf *conf) {
    if(conf) {
        if(conf->flowList)  {
            deleteFlowListElems(conf->flowList);
            deleteFlowList(conf->flowList);
        }
        uint32_t i;
        for(i = 0; i < conf->hash_size; i++) {
            deleteFlowList(conf->flowHashLists[i]);
        }
        free(conf->flowHashLists);

        free(conf);
    }
    return;
}

Flow *createNewFlowFromPacket(Packet *packet) {
    DBGPRINTF("createNewFlowFromPacket\n")

    Flow *flow = createNewFlow();

    if(flow && packet) {
        COPY_ADDR(&(packet->src), &(flow->src));
        COPY_ADDR(&(packet->dst), &(flow->dst));

        flow->sp = packet->sp;
        flow->dp = packet->dp;
        flow->proto = packet->proto;
        if(!packet->hash) {
            packet->hash = calculatePacketFlowHash(packet);
        }
        flow->flowHash = packet->hash;
        flow->initPacketTime = packet->enterTime;
        flow->toDstPktCnt = 1;
        flow->toDstByteCnt = packet->payloadLen;
        flow->toSrcPktCnt = 0;
        flow->toDstByteCnt = 0;
        packet->flow = flow;
    }

    DBGPRINTF("finished createNewFlowFromPacket\n");
    return flow;
}

Flow *getOrCreateFlowFromHash(Packet *packet) {
    DBGPRINTF("getOrCreateFlowFromHash\n")
    FlowList *flowList = NULL;
    FlowHash hash = packet->hash;
    Flow *flow;

    flowList = globalFlowCnf->flowHashLists[hash % globalFlowCnf->hash_size];

    if(flowList == NULL) {
        flowList = initNewFlowList();
        globalFlowCnf->flowHashLists[hash % globalFlowCnf->hash_size] = flowList;
    }

    flow = flowList->head;
    uint8_t found = 0;
    while(flow && !found) {
        if(CMP_FLOW(flow, packet))  found = 1;
        else flow = flow->nextFlow;
    }


    if(!flow) {
        if(globalFlowCnf->flowList->listSize < globalFlowCnf->maxFlow) {
            DBGPRINTF("creating new flow and adding it to lists\n");
            flow = createNewFlowFromPacket(packet);
            addFlowToList(flow, flowList);
            addFlowToList(flow, globalFlowCnf->flowList);
            DBGPRINTF("new number of followed flows: %u\n", globalFlowCnf->flowList->listSize);
        }
        else {
            DBGPRINTF("max number of flows reached, cannot open new Flow\n");
        }
    }
    else {
        DBGPRINTF("found existing flow\n");
        DBGPRINTF("number of followed flows: %u\n", globalFlowCnf->flowList->listSize);
        if(getPacketFlowDirection(flow, packet) == TO_SERVER) {
            flow->toDstByteCnt++;
            flow->toDstByteCnt += packet->payloadLen;
        }
        else {
            flow->toSrcPktCnt++;
            flow->toSrcByteCnt += packet->payloadLen;
        }
        flow->lastPacketTime = packet->enterTime;
    }

    return flow;
}

void swapFlowDirection(Flow *flow) {
    DBGPRINTF("swapFlowDirection\n");

    uint16_t portTemp = flow->sp;
    flow->sp = flow->dp;
    flow->dp = portTemp;

    Address addrTemp;
    COPY_ADDR(&flow->src, &addrTemp);
    COPY_ADDR(&flow->dst, &flow->src);
    COPY_ADDR(&addrTemp, &flow->dst);

    return;
}

int getFlowDirectionFromAddrs(Flow *flow, Address *src, Address *dst) {
    if(!CMP_ADDR(src, dst)) {
        if(CMP_ADDR(&flow->src, src)) {
            return TO_SERVER;
        }
        else {
            return TO_CLIENT;
        }
    }
    else {
        return -1;
    }
}

int getFlowDirectionFromPorts(Flow *flow, const Port sp, const Port dp) {
    if(!CMP_PORT(sp, dp)) {
        if(CMP_PORT(sp, flow->sp)) {
            return TO_SERVER;
        }
        else {
            return TO_CLIENT;
        }
    }
    else {
        return -1;
    }
}

int getPacketFlowDirection(Flow *flow, Packet *pkt) {
    DBGPRINTF("getPacketFlowDirection\n");
    int ret;

    if(pkt->proto == IPPROTO_TCP || pkt->proto == IPPROTO_UDP) {
        ret = getFlowDirectionFromPorts(flow, pkt->sp, pkt->dp);
        if(ret != -1) {
            return ret;
        }
        else {
            return getFlowDirectionFromAddrs(flow, &pkt->src, &pkt->dst);
        }
    }
    else if(pkt->proto == IPPROTO_ICMP || pkt->proto == IPPROTO_ICMPV6) {
        return getFlowDirectionFromAddrs(flow, &pkt->src, &pkt->dst);
    }
    return -1;
}

void printFlowInfo(Flow *flow) {
    DBGPRINTF("\n\n########## FLOW INFO ##########\n");

    DBGPRINTF("flow->src: %0X %0X %0X %0X\n",
              flow->src.addr_data32[0],
              flow->src.addr_data32[1],
              flow->src.addr_data32[2],
              flow->src.addr_data32[3]);

    DBGPRINTF("flow->dst: %0X %0X %0X %0X\n",
              flow->dst.addr_data32[0],
              flow->dst.addr_data32[1],
              flow->dst.addr_data32[2],
              flow->dst.addr_data32[3]);

    DBGPRINTF("flow->sp: %u\n", flow->sp);
    DBGPRINTF("flow->dp: %u\n", flow->dp);
    DBGPRINTF("flow->proto: %u\n", flow->proto);
    DBGPRINTF("flow->hash: %u\n", flow->flowHash);
    DBGPRINTF("flow->protoCtx: %p\n", flow->protoCtx);
    DBGPRINTF("flow->initPacketTime: %u\n", flow->initPacketTime);
    DBGPRINTF("flow->lastPacketTime: %u\n", flow->lastPacketTime);
    DBGPRINTF("flow->toDstPktCnt: %u\n", flow->toDstPktCnt);
    DBGPRINTF("flow->toSrcPktCnt: %u\n", flow->toSrcPktCnt);
    DBGPRINTF("flow->toDstByteCnt: %lu\n", flow->toDstByteCnt);
    DBGPRINTF("flow->toSrcByteCnt: %lu\n", flow->toSrcByteCnt);
    DBGPRINTF("flow->prevFlow: %p\n", flow->prevFlow);
    DBGPRINTF("flow->nextFlow: %p\n", flow->nextFlow);

    DBGPRINTF("\n\n########## END ##########\n");

    return;
}