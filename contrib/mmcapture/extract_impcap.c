/* extract_impcap.c
 *
 * This file contains functions to get fields given by Impcap
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

#include "extract_impcap.h"

Packet *getImpcapData(smsg_t *pMsg) {
    int localret;
    uint32_t contentLength;
    char *content;
    uint16_t ethType;
    struct json_object *pJson = NULL;
    struct json_object *obj = NULL;
    Packet *pkt = NULL;

    msgPropDescr_t *pDesc = malloc(sizeof(msgPropDescr_t));

    /* search for impcap packet metadata */
    msgPropDescrFill(pDesc, (uchar*)IMPCAP_METADATA, strlen(IMPCAP_METADATA));
    localret = msgGetJSONPropJSON(pMsg, pDesc, &pJson);
    if(!localret) {
        pkt = createPacket();

        if(fjson_object_object_get_ex(pJson, "ID", &obj)) {
            pkt->pktNumber = fjson_object_get_int(obj);
        }

        if (fjson_object_object_get_ex(pJson, "ETH_type", &obj)) {
            ethType = fjson_object_get_int(obj);
            if(ethType == ETHERTYPE_IPV4) {
                pkt->ipv4h = getIpv4Header(pJson);
                pkt->proto = pkt->ipv4h->proto;
            }
            else if(ethType == ETHERTYPE_IPV6) {
                pkt->ipv6h = getIpv6Header(pJson);
                pkt->proto = pkt->ipv6h->proto;
            }

            if(pkt->proto == IPPROTO_TCP) {
                pkt->tcph = getTcpHeader(pJson);
            }
        }

        updatePacketFromHeaders(pkt);

        msgPropDescrDestruct(pDesc);
        fjson_object_put(pJson);

        /* search impcap packet data */
        msgPropDescrFill(pDesc, (uchar*)IMPCAP_DATA, strlen(IMPCAP_DATA));
        localret = msgGetJSONPropJSON(pMsg, pDesc, &pJson);
        if(!localret) {
            DBGPRINTF("getting packet content\n");

            if(fjson_object_object_get_ex(pJson, "length", &obj)) {
                contentLength = fjson_object_get_int(obj);
                if(fjson_object_object_get_ex(pJson, "content", &obj)) {
                    content = fjson_object_get_string(obj);
                    pkt->payload = ImpcapDataDecode(content, contentLength);
                    pkt->payloadLen = contentLength/2;
                }
            }
        }
    }

    msgPropDescrDestruct(pDesc);
    free(pDesc);
    fjson_object_put(pJson);

    return pkt;
}

char *ImpcapDataDecode(char *hex, uint32_t length) {
    char *retBuf = malloc(length/2*sizeof(char));
    int i;

    for(i = 0; i < length; ++i) {
        if(i%2) {
            retBuf[i/2] <<= 4;
            if(hex[i] >= '0' && hex[i] <= '9') {
                retBuf[i/2] += hex[i] - '0';
            }
            else if(hex[i] >= 'A' && hex[i] <= 'F') {
                retBuf[i/2] += hex[i] - 'A' + 10;
            }
        }
        else {
            if(hex[i] >= '0' && hex[i] <= '9') {
                retBuf[i/2] = hex[i] - '0';
            }
            else if(hex[i] >= 'A' && hex[i] <= 'F') {
                retBuf[i/2] = hex[i] - 'A' + 10;
            }
        }
    }

    return retBuf;
}

TCPHdr *getTcpHeader(struct json_object *pJson) {
    DBGPRINTF("getting tcp header\n");
    struct json_object *obj = NULL;
    TCPHdr *tcph = calloc(1, sizeof(TCPHdr));

    if (fjson_object_object_get_ex(pJson, "net_src_port", &obj)) {
        tcph->sport = fjson_object_get_int(obj);
        DBGPRINTF("tcph->sport: %u\n", tcph->sport);
    }

    if (fjson_object_object_get_ex(pJson, "net_dst_port", &obj)) {
        tcph->dport = fjson_object_get_int(obj);
        DBGPRINTF("tcph->dport: %u\n", tcph->dport);
    }

    if (fjson_object_object_get_ex(pJson, "TCP_seq_number", &obj)) {
        tcph->seq = fjson_object_get_int64(obj);
        DBGPRINTF("tcph->seq: %u\n", tcph->seq);
    }

    if (fjson_object_object_get_ex(pJson, "TCP_ack_number", &obj)) {
        tcph->ack = fjson_object_get_int64(obj);
        DBGPRINTF("tcph->ack: %u\n", tcph->ack);
    }

    if (fjson_object_object_get_ex(pJson, "net_flags", &obj)) {
        strncpy(tcph->flags, fjson_object_get_string(obj), 10);
        DBGPRINTF("tcph->flags: %s\n", tcph->flags);
    }

    if (fjson_object_object_get_ex(pJson, "net_bytes_data", &obj)) {
        tcph->TCPDataLength = fjson_object_get_int(obj);
        DBGPRINTF("tcph->TCPDataLength: %u\n", tcph->TCPDataLength);
    }

    DBGPRINTF("finished getting tcp header\n");
    return tcph;
}

IPV6Hdr *getIpv6Header(struct json_object *pJson) {
    DBGPRINTF("getting IPV6 header\n");
    struct json_object *obj = NULL;
    IPV6Hdr *ipv6h = malloc(sizeof(IPV6Hdr));
    memset(ipv6h, 0, sizeof(IPV6Hdr));

    if(!ipv6h) {
        DBGPRINTF("ipv6h malloc failed\n");
    }

    if (fjson_object_object_get_ex(pJson, "net_dst_ip", &obj)) {
        strncpy(ipv6h->dst, fjson_object_get_string(obj), 32);
        DBGPRINTF("ip6h->dst: %s\n", ipv6h->dst);
    }

    if (fjson_object_object_get_ex(pJson, "net_src_ip", &obj)) {
        strncpy(ipv6h->src, fjson_object_get_string(obj), 32);
        DBGPRINTF("ip6h->src: %s\n", ipv6h->src);

    }

    if (fjson_object_object_get_ex(pJson, "net_ttl", &obj)) {
        ipv6h->ttl = fjson_object_get_int(obj);
        DBGPRINTF("ip6h->ttl: %d\n", ipv6h->ttl);
    }

    if (fjson_object_object_get_ex(pJson, "IP_proto", &obj)) {
        ipv6h->proto = fjson_object_get_int(obj);
        DBGPRINTF("ip6h->proto: %d\n", ipv6h->proto);
    }

    return ipv6h;
}

IPV4Hdr *getIpv4Header(struct json_object *pJson) {
    DBGPRINTF("getting IPV4 header\n");
    struct json_object *obj = NULL;
    IPV4Hdr *ipv4h = malloc(sizeof(IPV4Hdr));
    memset(ipv4h, 0, sizeof(IPV4Hdr));

    if (fjson_object_object_get_ex(pJson, "net_dst_ip", &obj)) {
        strncpy(ipv4h->dst, fjson_object_get_string(obj), 20);
        DBGPRINTF("ip4h->dst: %s\n", ipv4h->dst);
    }

    if (fjson_object_object_get_ex(pJson, "net_src_ip", &obj)) {
        strncpy(ipv4h->src, fjson_object_get_string(obj), 20);
        DBGPRINTF("ip4h->src: %s\n", ipv4h->src);
    }

    if (fjson_object_object_get_ex(pJson, "IP_ihl", &obj)) {
        ipv4h->hLen = fjson_object_get_int(obj);
        DBGPRINTF("ip4h->hLen: %d\n", ipv4h->hLen);
    }

    if (fjson_object_object_get_ex(pJson, "net_ttl", &obj)) {
        ipv4h->ttl = fjson_object_get_int(obj);
        DBGPRINTF("ip4h->ttl: %d\n", ipv4h->ttl);
    }

    if (fjson_object_object_get_ex(pJson, "IP_proto", &obj)) {
        ipv4h->proto = fjson_object_get_int(obj);
        DBGPRINTF("ip4h->proto: %d\n", ipv4h->proto);
    }

    return ipv4h;
}
