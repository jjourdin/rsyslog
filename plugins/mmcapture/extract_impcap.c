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
    int localret, isIp = 0;
    uint32_t contentLength;
    char *content;
    uint16_t ethType;
    struct json_object *pJson = NULL;
    struct json_object *obj = NULL;
    Packet *pkt = NULL;

    msgPropDescr_t *pDesc = malloc(sizeof(msgPropDescr_t));

    msgPropDescrFill(pDesc, (uchar*)IMPCAP_METADATA, strlen(IMPCAP_METADATA));
    localret = msgGetJSONPropJSON(pMsg, pDesc, &pJson);

    if(!localret) {
        pkt = malloc(sizeof(Packet));
        DBGPRINTF("message has impcap data\n");

        /* expect 'data' field to be present (*should* be the case if 'impcap' is here) */
        if(fjson_object_object_get_ex(pJson, "length", &obj)) {
            contentLength = fjson_object_get_int64(obj);
            DBGPRINTF("data content length: %d\n", contentLength);
            if(fjson_object_object_get_ex(pJson, "content", &obj)) {
                content = fjson_object_get_string(obj);
                pkt->payload = ImpcapDataDecode(content, contentLength);
                pkt->payloadLen = contentLength/2;
            }
        }

        if (fjson_object_object_get_ex(pJson, "ETH_type", &obj)) {
            ethType = fjson_object_get_int(obj);
            if(ethType == ETHERTYPE_IPV4) {
                isIp = 1;
                pkt->ipv4h = getIpv4Header(pJson);
                DBGPRINTF("packet is IPV4\n");
            }
            else if(ethType == ETHERTYPE_IPV6) {
                isIp = 1;
                pkt->ipv6h = getIpv6Header(pJson);
                DBGPRINTF("packet is IPV6\n");
            }

            if(isIp) {
                pkt->tcph = getTcpHeader(pJson);
                if(pkt->tcph != NULL) {
                    DBGPRINTF("packet is TCP\n");

                    if(pkt->tcph->dport == SMB_PORTS || pkt->tcph->sport == SMB_PORTS) {
                        pkt->smbh = getSmbHeader(pJson);
                    }
                }
            }
        }
    }

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
    TCPHdr *tcph = malloc(sizeof(TCPHdr));
    struct json_object *obj = NULL;

    if (fjson_object_object_get_ex(pJson, "net_src_port", &obj)) {
        tcph->sport = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "net_dst_port", &obj)) {
        tcph->dport = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "TCP_seq_number", &obj)) {
        tcph->seq = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "TCP_ack_number", &obj)) {
        tcph->ack = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "net_flags", &obj)) {
        tcph->flags = fjson_object_get_string(obj);
    }

    return tcph;
}

IPV6Hdr *getIpv6Header(struct json_object *pJson) {
    IPV6Hdr *ipv6h = malloc(sizeof(IPV6Hdr));
    struct json_object *obj = NULL;

    if (fjson_object_object_get_ex(pJson, "net_dst_ip", &obj)) {
        ipv6h->dst = fjson_object_get_string(obj);
    }

    if (fjson_object_object_get_ex(pJson, "net_src_ip", &obj)) {
        ipv6h->src = fjson_object_get_string(obj);
    }

    if (fjson_object_object_get_ex(pJson, "net_ttl", &obj)) {
        ipv6h->ttl = fjson_object_get_int(obj);
    }

    return ipv6h;
}

IPV4Hdr *getIpv4Header(struct json_object *pJson) {
    IPV4Hdr *ipv4h = malloc(sizeof(IPV4Hdr));
    struct json_object *obj = NULL;

    if (fjson_object_object_get_ex(pJson, "net_dst_ip", &obj)) {
        ipv4h->dst = fjson_object_get_string(obj);
    }

    if (fjson_object_object_get_ex(pJson, "net_src_ip", &obj)) {
        ipv4h->src = fjson_object_get_string(obj);
    }

    if (fjson_object_object_get_ex(pJson, "IP_ihl", &obj)) {
        ipv4h->hLen = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "net_ttl", &obj)) {
        ipv4h->ttl = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "IP_proto", &obj)) {
        ipv4h->proto = fjson_object_get_int(obj);
    }

    return ipv4h;
}

SMBHdr *getSmbHeader(struct json_object *pJson) {
    SMBHdr *smbh = malloc(sizeof(SMBHdr));
    struct json_object *obj = NULL;

    if (fjson_object_object_get_ex(pJson, "SMB_version", &obj)) {
        smbh->version = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_NTstatus", &obj)) {
        smbh->ntStatus = fjson_object_get_int64(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_operation", &obj)) {
        smbh->opcode = fjson_object_get_int(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_flags", &obj)) {
        smbh->flags = fjson_object_get_string(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_seqNumber", &obj)) {
        smbh->seqNumber = fjson_object_get_int64(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_processID", &obj)) {
        smbh->procID= fjson_object_get_int64(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_treeID", &obj)) {
        smbh->treeID = fjson_object_get_int64(obj);
    }

    if (fjson_object_object_get_ex(pJson, "SMB_userID", &obj)) {
        smbh->userID = fjson_object_get_int64(obj);
    }

    return smbh;
}