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

static inline void tcpConnectionPushToQueue(TcpConnection *connection, TcpQueue *newQueue) {
    DBGPRINTF("tcpConnectionPushToQueue\n");

    if(connection->queue) {
        newQueue->next = connection->queue;
        connection->queue->prev = newQueue;
    }
    connection->queue = newQueue;

    return;
}

static inline void tcpQueueListDelete(TcpQueue *head) {
    DBGPRINTF("tcpQueueListDelete\n");

    if(head) {
        if(head->next) tcpQueueListDelete(head->next);

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
        tcpQueueListDelete(tcpConnection->queue);
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
    DBGPRINTF("tcpConnectionsUpdateFromQueueElem\n");

    if(queue && srcCon && dstCon) {
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
            DBGPRINTF("data to get offset -> queue->seq: %u, srcCon->initSeq: %u\n", queue->seq, srcCon->initSeq);
            uint32_t offset = queue->seq - srcCon->initSeq - 1 /* SYN packet = seq+1 but no data */;
            if(srcCon->state > TCP_ESTABLISHED) {
                offset--; /* FIN packet = seq+1 but no data */
                DBGPRINTF("offset reduced as tcp state over established\n")
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

static inline int tcpConnectionCanPopFromQueue(TcpConnection *connection) {
    DBGPRINTF("tcpConnectionCanPopFromQueue\n");

    if(connection->queue) {
        if(connection->state > TCP_LISTEN) return connection->nextSeq == connection->queue->seq;
        else return 1;
    }

    return 0;
}

static inline TcpQueue *tcpConnectionGetNextInQueue(TcpConnection *connection) {
    DBGPRINTF("tcpConnectionGetNextInQueue\n");

    TcpQueue *scan = connection->queue;
    while(scan != NULL) {
        if(connection->nextSeq == scan->seq) return scan;
        scan = scan->next;
    }

    return NULL;
}

static inline int tcpQueueRemoveFromConnection(TcpConnection *connection, TcpQueue *queue) {
    DBGPRINTF("tcpQueueRemoveFromConnection\n");

    if(queue) {
        if(queue->prev) {
            queue->prev->next = queue->next;
        }
        if(queue->next) {
            queue->next->prev = queue->prev;
        }

        if(connection->queue == queue) {
            connection->queue = queue->next;
        }

        if(queue->data) free(queue->data);
        free(queue);
        return 0;
    }
    return 1;
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
                pkt->flow->protoCtx = (void *)session;
            }
            else
            {
                TcpConnection *srcCon, *dstCon;
                TcpQueue *tcpQueue = packetEnqueue(pkt);
                if(getPacketFlowDirection(pkt->flow, pkt) == TO_SERVER) {
                    srcCon = session->cCon;
                    dstCon = session->sCon;
                }
                else {
                    srcCon = session->sCon;
                    dstCon = session->cCon;
                }

                tcpConnectionPushToQueue(srcCon, tcpQueue);
                if(tcpConnectionCanPopFromQueue(srcCon)) {
                    do {
                        ret = tcpConnectionsUpdateFromQueueElem(srcCon, dstCon, tcpQueue);
                        tcpQueueRemoveFromConnection(srcCon, tcpQueue);
                        tcpQueue = tcpConnectionGetNextInQueue(srcCon);
                    }while(tcpQueue && !ret);
                }

                if(ret == 1) return 1;
            }
            printTcpSessionInfo(session);

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