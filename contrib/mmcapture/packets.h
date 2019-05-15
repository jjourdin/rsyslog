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

/* Address */
typedef struct Address_ {
    char family;
    union {
        uint32_t        address_un_data32[4]; /* type-specific field */
        uint16_t        address_un_data16[8]; /* type-specific field */
        uint8_t         address_un_data8[16]; /* type-specific field */
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

/* Port is just a uint16_t */
typedef uint16_t Port;

typedef struct Packet_ {
    Address src, dst;
    Port sp, dp;
    uint8_t proto;
    uint16_t vlanId[2];
    char *flags;

    struct Flow_ *flow;
    uint32_t flowHash;

    struct IPV6Hdr_ *ipv6h;
    struct IPV4Hdr_ *ipv4h;
    struct TCPHdr_ *tcph;
    struct SMBHdr_ *smbh;

    uint8_t *payload;
    uint16_t payloadLen;
} Packet;


// ##############################################


typedef struct tcp_metadata_s{
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seqNum;
  uint32_t ackNum;
  char *flags;
}tcp_metadata;

typedef struct app_header_metadata_s{
  uint8_t type;
    #define HEADER_TYPE_FTP   1
    #define HEADER_TYPE_HTTP  2
    #define HEADER_TYPE_SMB   3
  void *pHdr;
}app_header_metadata;

typedef struct smb_metadata_s {
  uint64_t sessID;
  uint16_t opCode;
  char *flags;
  uint64_t seqNum;
  uint32_t procID;
  uint32_t treeID;
}smb_metadata;

typedef struct tcp_payload_s{
  uint8_t *data;
  uint16_t length;
}tcp_payload;

typedef struct tcp_packet_s{
  tcp_metadata *meta;
  tcp_payload *pload;
  app_header_metadata *appHeader;
}tcp_packet;

void printPacketInfo(Packet *);
int getTCPMetadata(struct json_object *pJson, tcp_packet *pData);
int getSMBMetadata(struct json_object *pJson, tcp_packet *pData);
tcp_packet* createPacket();
void freePacket(tcp_packet *pPacket);

#endif /* PACKETS_H */
