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
    DBGPRINTF("tcpConnectionAddInQueue\n");

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

        DBGPRINTF("could not create new streamBuffer\n");
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
            TcpConnection *srcCon = tcpSession->cCon;
            TcpConnection *dstCon = tcpSession->sCon;
            TCPHdr *header = pkt->tcph;

            srcCon->initSeq = header->seq;
            srcCon->lastAck = header->ack;

            strncpy(flags, header->flags, 10);

            if(HAS_TCP_FLAG(flags, 'S') && HAS_TCP_FLAG(flags, 'A')) {
                // connection was initiated by the destination, we need to swap connections
                swapTcpConnections(tcpSession);
                swapFlowDirection(pkt->flow);
                srcCon->state = TCP_SYN_SENT;
                dstCon->state = TCP_SYN_RECV;
                srcCon->initSeq = header->ack-1;
                srcCon->nextSeq = header->ack;
                dstCon->nextSeq = header->seq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'S')) {
                // connection is beginning
                srcCon->state = TCP_SYN_SENT;
                dstCon->state = TCP_LISTEN;
                srcCon->nextSeq = srcCon->initSeq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'F')) {
                /* connection is closing, but specific state is unknown
                 * it's not a problem as there is still at least one packet to receive */
                dstCon->state = TCP_FIN_WAIT1;
                srcCon->state = TCP_CLOSE_WAIT;

                srcCon->nextSeq = header->seq + 1;
            }
            else if(HAS_TCP_FLAG(flags, 'A')) {
                // connection is established or closing
                srcCon->state = TCP_ESTABLISHED;
                dstCon->state = TCP_ESTABLISHED;
            }
            else {
                // probably RST or illegal state, dropping
                return 1;
            }


            if(tcpDataLength) {
                uint32_t dataLength = tcpDataLength;

                streamBufferAddDataSegment(srcCon->streamBuffer, 0, dataLength, pkt->payload);

                srcCon->nextSeq = srcCon->initSeq + dataLength;
            }

            return 0;
        }
    }

    return -1;
}

static inline int packetNeedsQueuing(TcpSession *session, Packet *pkt) {
    DBGPRINTF("packetNeedsQueuing\n");

    if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
        if(session->cCon->state > TCP_LISTEN) return session->cCon->nextSeq != pkt->tcph->seq;
    }
    else {
        if(session->sCon->state > TCP_LISTEN) return session->sCon->nextSeq != pkt->tcph->seq;
    }

    return 0;
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
            TCPHdr *header = pkt->tcph;

            strncpy(flags, header->flags, 10);

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
                srcCon->initSeq = header->seq;
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
                else if(srcCon->state == TCP_SYN_SENT) {
                    srcCon->state = TCP_ESTABLISHED;
                }

                if(dstCon->state == TCP_TIME_WAIT) {
                    dstCon->state = TCP_CLOSED;
                }
                else if(dstCon->state == TCP_LAST_ACK) {
                    dstCon->state = TCP_CLOSED;
                }
                else if(dstCon->state == TCP_SYN_RECV) {
                    dstCon->state = TCP_ESTABLISHED;
                }
            }
            else {
                DBGPRINTF("tcp session flags unhandled\n");
            }

            if(tcpDataLength) {
                uint32_t dataLength = tcpDataLength;
                uint32_t offset = header->seq - srcCon->initSeq - 1 /* SYN packet */;

                if(srcCon->state > TCP_ESTABLISHED) offset--; /* FIN packet */

                streamBufferAddDataSegment(srcCon->streamBuffer, offset, dataLength, pkt->payload);

                srcCon->nextSeq += tcpDataLength;
            }

            srcCon->lastAck = header->ack;

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
                    DBGPRINTF("packetNeedsQueuing: yes\n");
                    TcpQueue *tcpQueue = packetEnqueue(pkt);
                    if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
                        tcpConnectionAddInQueue(session->cCon, tcpQueue);
                    }
                    else {
                        tcpConnectionAddInQueue(session->sCon, tcpQueue);
                    }
                }
                else {
                    DBGPRINTF("packetNeedsQueuing: no\n");
                    tcpSessionUpdateFromPacket(session, pkt);
                }
            }
            printTcpSessionInfo(session);

            return 0;
        }
        return 1;
    }
    return -1;
}

void printTcpQueueInfo(TcpQueue *queue) {
    DBGPRINTF("\n\n########## TCPQUEUE INFO ##########\n");

    DBGPRINTF("tcpQueue->tcp_flags: %s\n", queue->tcp_flags);
    DBGPRINTF("tcpQueue->seq: %X\n", queue->seq);
    DBGPRINTF("tcpQueue->ack: %X\n", queue->ack);
    DBGPRINTF("tcpQueue->dataLength: %u\n", queue->dataLength);

    if(queue->next) printTcpQueueInfo(queue->next);

    DBGPRINTF("\n\n########## END TCPQUEUE INFO ##########\n");
    return;
}

void printTcpConnectionInfo(TcpConnection *connection) {
    DBGPRINTF("\n\n########## TCPCONNECTION INFO ##########\n");

    DBGPRINTF("connection->state: %u\n", connection->state);
    DBGPRINTF("connection->initSeq: %X\n", connection->initSeq);
    DBGPRINTF("connection->nextSeq: %X\n", connection->nextSeq);
    DBGPRINTF("connection->lastAck: %X\n", connection->lastAck);

    if(connection->queue) printTcpQueueInfo(connection->queue);
    if(connection->streamBuffer) printStreamBufferInfo(connection->streamBuffer);

    DBGPRINTF("\n\n########## END TCPCONNECTION INFO ##########\n");
    return;
}

void printTcpSessionInfo(TcpSession *session) {
    DBGPRINTF("\n\n########## TCPSESSION INFO ##########\n");

    if(session->cCon) printTcpConnectionInfo(session->cCon);
    if(session->sCon) printTcpConnectionInfo(session->sCon);

    DBGPRINTF("\n\n########## END TCPSESSION INFO ##########\n");
    return;
}