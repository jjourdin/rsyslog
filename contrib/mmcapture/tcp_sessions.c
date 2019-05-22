/* tcp_sessions.c
 *
 * This file contains functions to handle TCP sessions
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

#include "tcp_sessions.h"

static inline void tcpConnectionAddInQueue(TcpConnection *connection, TcpQueue *newQueue) {
    DBGPRINTF("tcpConnectionCreate\n");

    if(connection->queue) {
        newQueue->next = connection->queue;
    }
    connection->queue = newQueue;

    return;
}

static inline TcpConnection *tcpConnectionCreate() {
    DBGPRINTF("tcpConnectionCreate\n");

    TcpConnection *tcpConnection = calloc(1, sizeof(TcpConnection));

    if(tcpConnection) {
        tcpConnection->streamBuffer = streamBufferCreate();

        if(tcpConnection->streamBuffer) {
            return tcpConnection;
        }

        free(tcpConnection);
    }

    DBGPRINTF("could not create new TcpConnection\n");
    return NULL;
}

static inline void tcpConnectionDelete(TcpConnection *tcpConnection) {
    DBGPRINTF("tcpConnectionDelete\n");

    if(tcpConnection) {
        streamBufferDelete(tcpConnection->streamBuffer);
        free(tcpConnection->queue);
        free(tcpConnection);
    }

    return;
}

static inline TcpSession *tcpSessionCreate() {
    DBGPRINTF("tcpSessionCreate\n");

    TcpSession *tcpSession = calloc(1, sizeof(TcpSession));

    if(tcpSession) {
        tcpSession->cCon = tcpConnectionCreate();
        tcpSession->sCon = tcpConnectionCreate();

        if(tcpSession->cCon && tcpSession->sCon) {
            return tcpSession;
        }

        tcpConnectionDelete(tcpSession->cCon);
        tcpConnectionDelete(tcpSession->sCon);
        free(tcpSession);
    }

    DBGPRINTF("could not create new TcpSession\n");
    return NULL;
}

static inline void tcpSessionDelete(TcpSession *tcpSession) {
    DBGPRINTF("tcpSessionDelete\n");

    if(tcpSession) {
        tcpConnectionDelete(tcpSession->cCon);
        tcpConnectionDelete(tcpSession->sCon);
        free(tcpSession);
    }

    return;
}

static inline void swapTcpConnections(TcpSession *tcpSession) {
    TcpConnection *tmp = tcpSession->cCon;
    tcpSession->cCon = tcpSession->sCon;
    tcpSession->sCon = tmp;

    return;
}

int tcpSessionInitFromPacket(TcpSession *tcpSession, Packet *pkt) {
    DBGPRINTF("tcpSessionInitFromPacket\n");

    if(pkt && tcpSession) {
        if(pkt->proto == IPPROTO_TCP && pkt->tcph) {
            char flags[10];
            uint32_t tcpDataLength = pkt->payloadLen;

            tcpSession->cCon->initSeq = pkt->tcph->seq;
            tcpSession->cCon->lastAck = pkt->tcph->ack;

            strncpy(flags, pkt->tcph->flags, 10);

            if(HAS_TCP_FLAG(flags, 'S') && HAS_TCP_FLAG(flags, 'A')) {
                // connection was initiated by the destination, we need to swap connections
                swapTcpConnections(tcpSession);
                swapFlowDirection(pkt->flow);
                tcpSession->cCon->state = TCP_SYN_SENT;
                tcpSession->sCon->state = TCP_SYN_RECV;
                tcpSession->cCon->initSeq = pkt->tcph->ack-1;
                tcpSession->cCon->nextSeq = pkt->tcph->ack;
                tcpSession->sCon->nextSeq = pkt->tcph->seq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'S')) {
                // connection is beginning
                tcpSession->cCon->state = TCP_SYN_SENT;
                tcpSession->sCon->state = TCP_LISTEN;
                tcpSession->cCon->nextSeq = tcpSession->cCon->initSeq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'F')) {
                /* connection is closing, but specific state is unknown
                 * it's not a problem as there is still at least one packet to receive */
                tcpSession->sCon->state = TCP_FIN_WAIT1;
                tcpSession->cCon->state = TCP_CLOSE_WAIT;

                tcpSession->cCon->nextSeq = pkt->tcph->seq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'A')) {
                // connection is established or closing
                tcpSession->cCon->state = TCP_ESTABLISHED;
                tcpSession->sCon->state = TCP_ESTABLISHED;

                tcpSession->cCon->nextSeq = tcpSession->cCon->initSeq + tcpDataLength;

                if(pkt->payloadLen) {
                    StreamBufferSegment sbs;
                    sbs.length = pkt->payloadLen;
                    sbs.streamOffset = pkt->tcph->seq - tcpSession->cCon->initSeq - 1;
                    sbs.streamBuffer = tcpSession->cCon->streamBuffer;

                    streamBufferAddDataAtSegment(&sbs, pkt->payload);
                }
            }
            else {
                // probably RST or illegal state, dropping
                return 1;
            }
            return 0;
        }
    }

    return -1;
}

static inline int packetNeedsQueuing(TcpSession *session, Packet *pkt) {
    DBGPRINTF("packetNeedsQueuing\n");

    if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
        return session->cCon->nextSeq != pkt->tcph->seq;
    }
    else {
        return session->sCon->nextSeq != pkt->tcph->seq;
    }
}

static inline TcpQueue *packetEnqueue(Packet *pkt) {
    DBGPRINTF("packetEnqueue\n");

    TcpQueue *queue = calloc(1, sizeof(TcpQueue));

    if(queue) {
        strncpy(queue->tcp_flags, pkt->tcph->flags, 10);
        queue->seq = pkt->tcph->seq;
        queue->ack = pkt->tcph->ack;
        queue->dataLength = pkt->payloadLen;
        if(queue->dataLength) {
            queue->data = calloc(1, queue->dataLength);
            memmove(queue->data, pkt->payload, queue->dataLength);
        }
    }
    else {
        DBGPRINTF("could not create TcpQueue\n");
    }

    return queue;
}

int tcpSessionUpdateFromPacket(TcpSession *tcpSession, Packet *pkt) {
    DBGPRINTF("tcpSessionUpdateFromPacket\n");

    if(pkt && tcpSession) {
        if(pkt->proto == IPPROTO_TCP && pkt->tcph) {
            char flags[10];
            uint32_t tcpDataLength = pkt->payloadLen;

            strncpy(flags, pkt->tcph->flags, 10);

            TcpConnection *srcCon, *dstCon;
            if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
                srcCon = tcpSession->cCon;
                dstCon = tcpSession->sCon;
            }
            else {
                srcCon = tcpSession->sCon;
                dstCon = tcpSession->cCon;
            }

            if(HAS_TCP_FLAG(flags, 'R')){
                srcCon->state = TCP_CLOSED;
                dstCon->state = TCP_CLOSED;
                DBGPRINTF("tcp session RESET\n");
            }
            else if(HAS_TCP_FLAG(flags, 'S') && HAS_TCP_FLAG(flags, 'A')) {
                srcCon->state = TCP_SYN_RECV;
                srcCon->initSeq = pkt->tcph->seq;
                srcCon->nextSeq = srcCon->initSeq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'F')) {
                srcCon->nextSeq += 1;

                if(srcCon->state == TCP_CLOSE_WAIT) {
                    srcCon->state = TCP_LAST_ACK;
                }
                else if(srcCon->state == TCP_ESTABLISHED) {
                    srcCon->state = TCP_FIN_WAIT1;
                    /* to ease computation, we assume destination
                     * received this packet */
                    dstCon->state = TCP_CLOSE_WAIT;
                }
            }
            else if(HAS_TCP_FLAG(flags, 'A')) {
                if(srcCon->state == TCP_FIN_WAIT1) {
                    srcCon->state = TCP_CLOSING;
                }
                else if(srcCon->state == TCP_FIN_WAIT2) {
                    srcCon->state = TCP_TIME_WAIT;
                }

                if(dstCon->state == TCP_TIME_WAIT) {
                    dstCon->state = TCP_CLOSED;
                }
                else if(dstCon->state == TCP_LAST_ACK) {
                    dstCon->state = TCP_CLOSED;
                }

                if(srcCon->state == TCP_ESTABLISHED) {
                    if(pkt->payloadLen) {
                        StreamBufferSegment sbs;
                        sbs.length = pkt->payloadLen;
                        sbs.streamOffset = pkt->tcph->seq - srcCon->initSeq - 1;
                        sbs.streamBuffer = srcCon->streamBuffer;

                        streamBufferAddDataAtSegment(&sbs, pkt->payload);

                        srcCon->nextSeq += pkt->payloadLen;
                    }
                }
            }
            else {
                DBGPRINTF("tcp session flags unhandled\n");
            }

            srcCon->lastAck = pkt->tcph->ack;

            return 0;
        }
        return 1;
    }
    return -1;
}

int handleTcpFromPacket(Packet *pkt) {
    DBGPRINTF("handleTcpFromPacket\n");

    if(pkt) {
        if(pkt->proto == IPPROTO_TCP) {
            TcpSession *session = (TcpSession *)pkt->flow->protoCtx;

            if(!session) {
                session = tcpSessionCreate();
                tcpSessionInitFromPacket(session, pkt);
                pkt->flow->protoCtx = (void *)session;
            }
            else
            {
                if(packetNeedsQueuing(session, pkt)) {
                    TcpQueue *tcpQueue = packetEnqueue(pkt);
                    if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
                        tcpConnectionAddInQueue(session->cCon->queue, tcpQueue);
                    }
                    else {
                        tcpConnectionAddInQueue(session->sCon->queue, tcpQueue);
                    }
                }
                else {
                    tcpSessionUpdateFromPacket(session, pkt);
                }
            }
            return 0;
        }
        return 1;
    }
    return -1;
}