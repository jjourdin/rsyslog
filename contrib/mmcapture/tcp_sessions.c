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

static inline void tcpQueueListDelete(TcpQueue *head) {
    DBGPRINTF("tcpQueueListDelete\n");

    if(head) {
        if(head->prev) tcpQueueListDelete(head->prev);

        if(head->data) free(head->data);
        free(head);
    }
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
        tcpQueueListDelete(tcpConnection->queueHead);
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

void tcpSessionDelete(TcpSession *tcpSession) {
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

static inline TcpQueue *packetEnqueue(Packet *pkt) {
    DBGPRINTF("packetEnqueue\n");

    TcpQueue *queue = calloc(1, sizeof(TcpQueue));

    if(queue) {
        strncpy(queue->tcp_flags, pkt->tcph->flags, 10);
        queue->seq = pkt->tcph->seq;
        queue->ack = pkt->tcph->ack;
        queue->dataLength = pkt->tcph->TCPDataLength;
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

int tcpSessionInitFromPacket(TcpSession *tcpSession, Packet *pkt) {
    DBGPRINTF("tcpSessionInitFromPacket\n");

    if(pkt && tcpSession) {
        if(pkt->proto == IPPROTO_TCP && pkt->tcph) {
            char flags[10];
            uint32_t tcpDataLength = pkt->tcph->TCPDataLength;
            TcpConnection *srcCon = tcpSession->cCon;
            TcpConnection *dstCon = tcpSession->sCon;
            TCPHdr *header = pkt->tcph;

            srcCon->initSeq = header->seq;
            srcCon->lastAck = header->ack;
            srcCon->sPort = pkt->sp;
            dstCon->sPort = pkt->dp;
            tcpSession->flow = pkt->flow;

            strncpy(flags, header->flags, 10);

            if(HAS_TCP_FLAG(flags, 'S') && HAS_TCP_FLAG(flags, 'A')) {
                // connection was initiated by the destination, we need to swap connections
                swapTcpConnections(tcpSession);
                swapFlowDirection(tcpSession->flow);
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

int tcpConnectionsUpdateFromQueueElem(TcpConnection *srcCon, TcpConnection *dstCon, TcpQueue *queue) {
    DBGPRINTF("tcpConnectionsUpdateFromQueueElem: updating for packet seq=%X\n", queue->seq);

    if(queue && srcCon && dstCon) {
        queue->used = 1;

        char flags[10];
        uint32_t tcpDataLength = queue->dataLength;

        strncpy(flags, queue->tcp_flags, 10);

        // if connection was init while active
        if(!srcCon->initSeq) {
            srcCon->initSeq = queue->seq - 1; /* to "simulate" influence of SYN packet for dataLength calculations */
            srcCon->nextSeq = srcCon->initSeq + 1;
        }

        if(tcpDataLength) {
            uint32_t dataLength = tcpDataLength;
            uint32_t offset = queue->seq - srcCon->initSeq - 1 /* SYN packet = seq+1 but no data */;
            if(srcCon->state > TCP_ESTABLISHED && offset > 0) {
                offset--; /* FIN packet = seq+1 but no data */
            }

            streamBufferAddDataSegment(srcCon->streamBuffer, offset, dataLength, queue->data);
            srcCon->nextSeq += tcpDataLength;
        }

        if(HAS_TCP_FLAG(flags, 'R')){
            srcCon->state = TCP_CLOSED;
            dstCon->state = TCP_CLOSED;
            DBGPRINTF("tcp session RESET\n");
        }
        else if(HAS_TCP_FLAG(flags, 'S') && HAS_TCP_FLAG(flags, 'A')) {
            srcCon->state = TCP_SYN_RECV;
            srcCon->initSeq = queue->seq;
            srcCon->nextSeq = srcCon->initSeq + 1;
        }
        else if(HAS_TCP_FLAG(flags, 'F')) {
            srcCon->nextSeq += 1;

            if(srcCon->state == TCP_CLOSE_WAIT) {
                srcCon->state = TCP_LAST_ACK;
            }
            else if(srcCon->state <= TCP_ESTABLISHED) {
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
            else if(srcCon->state <= TCP_SYN_SENT) {
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

        srcCon->lastAck = queue->ack;

        if(srcCon->state >= TCP_CLOSING && dstCon->state >= TCP_CLOSING) {
            return 1;
        }

        return 0;
    }
    return -1;
}

static inline void tcpConnectionInsertToQueue(TcpConnection *connection, TcpQueue *newElem) {
    DBGPRINTF("tcpConnectionInsertToQueue");

    if(connection && newElem) {
        TcpQueue *scan;
        for(scan = connection->queueHead; scan != NULL && newElem->seq < scan->seq; scan = scan->prev) {}
        if(scan) {
            newElem->next = scan->next;
            newElem->prev = scan;
            if(scan->next) scan->next->prev = newElem;
            else connection->queueHead = newElem;
            scan->next = newElem;
        }
        else {
            if(connection->queueTail) {
                connection->queueTail->prev = newElem;
                newElem->next = connection->queueTail;
            }
            connection->queueTail = newElem;
        }
        if(!connection->queueHead) connection->queueHead = newElem;
    }
    else {
        DBGPRINTF("tcpConnectionInsertToQueue: [ERROR] connection or newElem are NULL\n");
    }

    return;
}

static inline TcpQueue *tcpConnectionGetNextInQueue(TcpConnection *connection) {
    DBGPRINTF("tcpConnectionGetNextInQueue\n");

    if(connection->state <= TCP_LISTEN) return connection->queueTail;

    TcpQueue *scan = connection->queueHead;
    while(scan != NULL) {
        if(connection->nextSeq == scan->seq && !scan->used) return scan;
        if(scan->seq < connection->nextSeq) return NULL;
        scan = scan->prev;
    }

    return NULL;
}

static inline int tcpQueueRemoveFromConnection(TcpConnection *connection, TcpQueue *queue) {
    DBGPRINTF("tcpQueueRemoveFromConnection\n");

    if(queue) {
        if(queue->prev) queue->prev->next = queue->next;
        if(queue->next) queue->next->prev = queue->prev;

        if(connection->queueHead == queue) connection->queueHead = queue->prev;
        if(connection->queueTail == queue) connection->queueTail = queue->next;

        if(queue->data) free(queue->data);
        free(queue);
        return 0;
    }
    return 1;
}

TcpConnection *getTcpSrcConnectionFromPacket(TcpSession *session, Packet *pkt) {
    if(session && pkt) {
        if(session->cCon->sPort == pkt->sp) return session->cCon;
        else if(session->sCon->sPort == pkt->sp) return session->sCon;
    }
    return NULL;
}

TcpConnection *getTcpDstConnectionFromPacket(TcpSession *session, Packet *pkt) {
    if(session && pkt) {
        if(session->cCon->sPort == pkt->dp) return session->cCon;
        else if(session->sCon->sPort == pkt->dp) return session->sCon;
    }
    return NULL;
}

int handleTcpFromPacket(Packet *pkt) {
    DBGPRINTF("handleTcpFromPacket\n");

    int ret = 0;

    if(pkt) {
        if(pkt->proto == IPPROTO_TCP) {
            TcpSession *session = (TcpSession *)pkt->flow->protoCtx;

            if(!session) {
                session = tcpSessionCreate();
                tcpSessionInitFromPacket(session, pkt);
                TcpQueue *tcpQueue = packetEnqueue(pkt);
                tcpConnectionInsertToQueue(session->cCon, tcpQueue);
                tcpQueue->used = 1;
                pkt->flow->protoCtx = (void *)session;
            }
            else
            {
                TcpConnection *srcCon, *dstCon;
                TcpQueue *tcpQueue = packetEnqueue(pkt);
                srcCon = getTcpSrcConnectionFromPacket(session, pkt);
                dstCon = getTcpDstConnectionFromPacket(session, pkt);

                tcpConnectionInsertToQueue(srcCon, tcpQueue);
                tcpQueue = tcpConnectionGetNextInQueue(srcCon);
                if(tcpQueue) {
                    do {
                        ret = tcpConnectionsUpdateFromQueueElem(srcCon, dstCon, tcpQueue);
                        tcpQueue = tcpConnectionGetNextInQueue(srcCon);
                    }while(tcpQueue && !ret);
                }

                if(srcCon->state >= TCP_ESTABLISHED &&
                dstCon->state >= TCP_ESTABLISHED &&
                (!srcCon->streamBuffer->bufferDump->pFile || !dstCon->streamBuffer->bufferDump->pFile)) {
                    char fileNameClient[100], fileNameServer[100];

                    snprintf(fileNameClient,
                             100, "tcp[%s->%s](%d->%d).dmp",
                             getAddrString(session->flow->src),
                             getAddrString(session->flow->dst),
                             session->flow->sp, session->flow->dp);
                    snprintf(fileNameServer,
                             100, "tcp[%s->%s](%d->%d).dmp",
                             getAddrString(session->flow->dst),
                             getAddrString(session->flow->src),
                             session->flow->dp, session->flow->sp);

                    if(linkStreamBufferToDumpFile(session->cCon->streamBuffer, fileNameClient) != 0) {
                        DBGPRINTF("could not link file to stream\n");
                    }
                    if(linkStreamBufferToDumpFile(session->sCon->streamBuffer, fileNameServer) != 0) {
                        DBGPRINTF("could not link file to stream\n");
                    }
                }

                if(ret == 1) return 1;
            }
            //printTcpSessionInfo(session);

            return 0;
        }
    }
    return -1;
}

void printTcpQueueInfo(TcpQueue *queue) {
    DBGPRINTF("\n\n########## TCPQUEUE INFO ##########\n");

    DBGPRINTF("tcpQueue->tcp_flags: %s\n", queue->tcp_flags);
    DBGPRINTF("tcpQueue->seq: %X\n", queue->seq);
    DBGPRINTF("tcpQueue->ack: %X\n", queue->ack);
    DBGPRINTF("tcpQueue->dataLength: %u\n", queue->dataLength);
    DBGPRINTF("tcpQueue->used: %u\n", queue->used);

    if(queue->prev) printTcpQueueInfo(queue->prev);

    DBGPRINTF("\n\n########## END TCPQUEUE INFO ##########\n");
    return;
}

void printTcpConnectionInfo(TcpConnection *connection) {
    DBGPRINTF("\n\n########## TCPCONNECTION INFO ##########\n");

    DBGPRINTF("connection->sPort: %u\n", connection->sPort);
    DBGPRINTF("connection->state: %u\n", connection->state);
    DBGPRINTF("connection->initSeq: %X\n", connection->initSeq);
    DBGPRINTF("connection->nextSeq: %X\n", connection->nextSeq);
    DBGPRINTF("connection->lastAck: %X\n", connection->lastAck);

    if(connection->queueHead) printTcpQueueInfo(connection->queueHead);
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