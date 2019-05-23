/* tcp_sessions.h
 *
 * This header contains the definition of TCP sessions structures
 * as well as prototypes for tcp_sessions.c
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

#ifndef TCP_SESSIONS_H
#define TCP_SESSIONS_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "packets.h"
#include "stream_buffer.h"

#define MAX_TCP_SESSIONS 512
#define TCP_PROTO 6

#define HAS_TCP_FLAG(flags, flag) ((strchr(flags, flag) == NULL) ? 0 : 1)

typedef struct TcpQueue_ {
    char tcp_flags[10];
    uint32_t seq;
    uint32_t ack;
    uint32_t dataLength;
    uint8_t *data;
    struct TcpQueue_ *next;
} TcpQueue;

enum tcpState
{
    TCP_NONE,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_CLOSED,
};

typedef struct TcpConnection_{
    enum tcpState state;
    uint32_t initSeq;
    uint32_t nextSeq;
    uint32_t lastAck;
    StreamBuffer *streamBuffer;
    TcpQueue *queue;
} TcpConnection;

typedef struct TcpSession_{
    TcpConnection *cCon;
    TcpConnection *sCon;
} TcpSession;

int tcpSessionInitFromPacket(TcpSession *, Packet *);
int tcpSessionUpdateFromPacket(TcpSession *, Packet *);
int handleTcpFromPacket(Packet *);
void printTcpQueueInfo(TcpQueue *);
void printTcpConnectionInfo(TcpConnection *);
void printTcpSessionInfo(TcpSession *);

#endif /* TCP_SESSIONS_H */
