/* packets.h
 *
 * This header contains the definition of internal structures
 * representing packets metadata and payload, as well as prototypes
 * for packets.c
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

#ifndef PACKETS_H
#define PACKETS_H

#include <stdlib.h>
#include <json.h>

#include "rsyslog.h"
#include "extract_impcap.h"
#include "flow.h"
#include "hash_utils.h"

/* Port is just a uint16_t */
typedef uint16_t Port;

/* Address */
typedef struct Address_ {
    char family;
    union {
        uint32_t        address_un_data32[4]; /* type-specific field */
        uint16_t        address_un_data16[8]; /* type-specific field */
        uint8_t         address_un_data8[16]; /* type-specific field */
        struct in6_addr address_un_in6;
    } address;
} Address;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8
#define addr_in6addr    address.address_un_in6

#define COPY_ADDR(a, b) do {                    \
        (b)->family = (a)->family;                 \
        (b)->addr_data32[0] = (a)->addr_data32[0]; \
        (b)->addr_data32[1] = (a)->addr_data32[1]; \
        (b)->addr_data32[2] = (a)->addr_data32[2]; \
        (b)->addr_data32[3] = (a)->addr_data32[3]; \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) do {       \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

#define CMP_ADDR(a1, a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))

typedef struct Packet_ {
    Address src, dst;
    Port sp, dp;
    uint8_t proto;

    struct Flow_ *flow;
    FlowHash hash;

    uint8_t flags;
#define PKT_ADDRS_KNOWN 0x01
#define PKT_PORTS_KNOWN 0x02
#define PKT_PROTO_KNOWN 0x04
#define PKT_HASH_READY  0x08
#define PKT_IPV4_ADDR   0x10
#define PKT_IPV6_ADDR   0x20

    struct IPV6Hdr_ *ipv6h;
    struct IPV4Hdr_ *ipv4h;
    struct TCPHdr_ *tcph;
    struct SMBHdr_ *smbh;

    uint8_t *payload;
    uint16_t payloadLen;

    uint32_t pktNumber;
} Packet;

void printPacketInfo(Packet *);
Packet *createPacket();
void freePacket(Packet *);
void updatePacketFromHeaders(struct Packet_ *);
FlowHash calculatePacketFlowHash(Packet *);

#endif /* PACKETS_H */
