/* smb_parser.c
 *
 * This file contains functions to parse SMB (version 2 and 3) headers.
 *
 * File begun on 2018-11-13
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

#include "parser.h"


struct dns_header_s {
	uint32_t version;
	uint16_t headerLength;
	uint16_t padding1;
	uint32_t ntStatus;
	uint16_t opCode;
	uint16_t padding2;
	uint32_t flags;
	uint32_t chainOffset;
	uint32_t comSeqNumber[2];
	uint32_t processID;
	uint32_t treeID;
	uint32_t userID[2];
	uint32_t signature[4];
};

typedef struct dns_header_s dns_header_t;

/* List of RCodes defined in RFC6895 : https://tools.ietf.org/html/rfc6895 */
static const char *dns_rcodes[] = {
		"NoError",  // 0
		"FormErr",  // 1
		"ServFail", // 2
		"NXDomain", // 3
		"NotImp",   // 4
		"Refused",  // 5
		"YXDomain", // 6
		"YXRRSet",  // 7
		"NXRRSet",  // 8
		"NotAuth",  // 9
		"NotZone",  // 10
		"",         // 11 - Reserved
		"",         // 12 - Reserved
		"",         // 13 - Reserved
		"",         // 14 - Reserved
		"",         // 15 - Reserved
		"BADVERS|BADSIG", // 16
		"BADKEY",   // 17
		"BADTIME",  // 18
		"BADMODE",  // 19
		"BADNAME",  // 20
		"BADALG",   // 21
		"BADTRUNC",  // 22
		/* Reserved for private use */
		NULL
};

/* List of record types (maybe not complete) */
static const char *dns_types[] = {
		0,
		"A",        // 1
		"NS",       // 2
		"MD", // 3
		"MF", // 4
		"CNAME",   // 5
		"SOA",  // 6
		"MB", // 7
		"MG",  // 8
		"MR",  // 9
		"NULL",  // 10
		"WKS",  // 11
		"PTR",         // 12
		"HINFO",         // 13
		"MINFO",         // 14
		"MX",         // 15
		"TXT",         // 16
		"RP",  // 17
		"AFSDB",   // 18
		"X25",  // 19
		"ISDN",  // 20
		"RT",  // 21
		"NSAP",   // 22
		"NSAP-PTR", // 23
		"SIG",   // 22
		"KEY",   // 22
		"PX",   // 22
		"GPOS",   // 22
		"AAAA",   // 22
		"LOC",   // 22
		"NXT",   // 22
		"EID",   // 22
		"NIMLOC",   // 22
		"SRV",   // 22
		"ATMA",   // 22
		"NAPTR",   // 22
		"KX",   // 22
		"CERT",   // 22
		"A6",   // 22
		"DNAME",   // 22
		"SINK",   // 22
		"OPT",   // 22
		"APL",   // 22
		"DS",   // 22
		"SSHFP",   // 22
		"IPSECKEY",   // 22
		"RRSIG",   // 22
		"NSEC",   // 22
		"DNSKEY",   // 22
		"DHCID",   // 22
		"NSEC3",   // 22
		"NSEC3PARAM",   // 22
		"TLSA",   // 22
		"SMIMEA",   // 22
		"Unassigned",   // 22
		"HIP",   // 22
		"NINFO",   // 22
		"RKEY",   // 22
		"TALINK",   // 22
		"CDS",   // 22
		"CDNSKEY",   // 22
		"OPENPGPKEY",   // 22
		"CSYNC",   // 22
		"ZONEMD",   // 63
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		"SPF",   // 99
		"UINFO",   // 22
		"UID",   // 22
		"GID",   // 22
		"UNSPEC",   // 22
		"NID",   // 22
		"L32",   // 22
		"L64",   // 22
		"LP",   // 22
		"EUI48",   // 22
		"EUI64",   // 109
		/* Reserved for private use */
		NULL
};
/* Part 2, since 249. To prevent useless large buffer in memory */
static const char *dns_types2[] = {
		"TKEY",
		"TSIG",
		"IXFR",
		"AXFR",
		"MAILB",
		"MAILA",
		"*",
		"URI",
		"CAA",
		"AVC",
		"DOA",
		"AMTRELAY",
		NULL
};
/* Part 3, since 32768. To prevent useless large buffer in memory */
static const char *dns_types3[] = {
		"TA",
		"DLV",
		NULL
};


/*  */
const char *get_type(uint16_t x) {
	const char **types = NULL;
	if( x >= 32768 )
		types = dns_types3;
	else if( x >= 249 )
		types = dns_types2;
	else
		types = dns_types;

	if( types[x] != NULL )
		return types[x];
	return "UNKNOWN";
}


/*  */
const char *get_class(uint16_t x) {
	switch(x) {
		case 1: return "IN";
		case 3: return "CH";
		case 4: return "HS";
		case 254: return "QCLASS NONE";
		case 255: return "QCLASS *";
		break;
	}
	return "UNKNOWN";
}


/*
 *  This function parses the bytes in the received packet to extract SMB2 metadata.
 *
 *  its parameters are:
 *    - a pointer on the list of bytes representing the packet
 *        the beginning of the header will be checked by the function
 *    - the size of the list passed as first parameter
 *    - a pointer on a json_object, containing all the metadata recovered so far
 *      this is also where SMB2 metadata will be added
 *
 *  This function returns a structure containing the data unprocessed by this parser
 *  or the ones after (as a list of bytes), and the length of this data.
*/
data_ret_t *dns_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
	const uchar *svg_packet = packet;
	DBGPRINTF("dns_parse\n");
	DBGPRINTF("packet size %d\n", pktSize);

	/* Union to prevent cast from uchar to smb_header_t */
	union {
		unsigned short int *two_bytes;
		const uchar *pckt;
	} union_short_int;

	/* Get transaction id */
	union_short_int.pckt = packet;
	unsigned short int transaction_id = ntohs(*(union_short_int.two_bytes));
	//DBGPRINTF("transaction_id = %02x \n", transaction_id);
	packet += 2;

	/* Get flags */
	union_short_int.pckt = packet;
	unsigned short int flags = ntohs(*(union_short_int.two_bytes));
	//DBGPRINTF("flags = %02x \n", flags);

	/* Get response flag */
	unsigned short int response_flag = (flags >> 15) & 0b1; // Get the left bit
	//DBGPRINTF("response_flag = %02x \n", response_flag);

	/* Get Opcode */
	unsigned short int opcode = (flags >> 11) & 0b1111;
	//DBGPRINTF("opcode = %02x \n", opcode);

	/* Verify Z: reserved bit */
	unsigned short int reserved = (flags >> 6) & 0b1;
	//DBGPRINTF("reserved = %02x \n", reserved);
	/* Reserved bit MUST be 0 */
	if (reserved != 0) {
		DBGPRINTF("DNS packet reserved bit (Z) is not 0, aborting message. \n");
		RETURN_DATA_AFTER(0)
	}

	/* Get reply code : 4 last bits */
	unsigned short int reply_code = flags & 0b1111;
	//DBGPRINTF("reply_code = %02x \n", reply_code);

	packet += 2;

	/* Get QDCOUNT */
	union_short_int.pckt = packet;
	unsigned short int query_count = ntohs(*(union_short_int.two_bytes));
	//DBGPRINTF("query_count = %02x \n", query_count);
	packet += 2;

	/* Get ANCOUNT */
	union_short_int.pckt = packet;
	unsigned short int answer_count = ntohs(*(union_short_int.two_bytes));
	//DBGPRINTF("answer_count = %02x \n", answer_count);
	packet += 2;

	/* Get NSCOUNT */
	union_short_int.pckt = packet;
	unsigned short int authority_count = ntohs(*(union_short_int.two_bytes));
	//DBGPRINTF("authority_count = %02x \n", authority_count);
	packet += 2;

	/* Get ARCOUNT */
	union_short_int.pckt = packet;
	unsigned short int additionnal_count = ntohs(*(union_short_int.two_bytes));
	//DBGPRINTF("additionnal_count = %02x \n", additionnal_count);
	packet += 2;

	fjson_object *queries =NULL;
	if( (queries=json_object_new_array()) == NULL ) {
		DBGPRINTF("impcap::dns_parser: Cannot create new json array. Stopping.");
		RETURN_DATA_AFTER((int) (packet - svg_packet))
	}

	// FOr each query of query_count
	int query_cpt = 0;
	while( query_cpt < query_count && (int)(packet-svg_packet) < pktSize ) {
		if( strlen((const char *) packet) >= 256 ) {
			DBGPRINTF("impcap::dns_parser: Length of domain queried is > 256. Stopping.");
			RETURN_DATA_AFTER((int) (packet - svg_packet))
		}
		fjson_object *query=NULL;
		if( (query=json_object_new_object()) == NULL ) {
			DBGPRINTF("impcap::dns_parser: Cannot create new json object. Stopping.");
			RETURN_DATA_AFTER((int) (packet - svg_packet))
		}
		char domain_query[256] = {0};
		uchar nb_char = *packet;
		packet++;
		int cpt = 0;
		while (*packet != '\0') {
			if (nb_char == 0) {
				nb_char = *packet;
				domain_query[cpt] = '.';
			} else {
				domain_query[cpt] = (char) *packet;
				nb_char--;
			}
			cpt++;
			packet++;
		}
		packet++; // pass the last \0
		DBGPRINTF("Requested domain : '%s' \n", domain_query);
		/* Register the name in dict */
		json_object_object_add(query, "name", json_object_new_string(domain_query));
		/* Get QTYPE */
		union_short_int.pckt = packet;
		unsigned short int qtype = ntohs(*(union_short_int.two_bytes));
		//DBGPRINTF("qtype = %02x \n", qtype);
		json_object_object_add(query, "qtype", json_object_new_int((int)qtype));
		json_object_object_add(query, "type", json_object_new_string(get_type(qtype)));
		packet += 2;
		/* Retrieve QCLASS */
		union_short_int.pckt = packet;
		unsigned short int qclass = ntohs(*(union_short_int.two_bytes));
		//DBGPRINTF("qclass = %02x \n", qclass);
		json_object_object_add(query, "qclass", json_object_new_int((int)qclass));
		json_object_object_add(query, "class", json_object_new_string(get_class(qclass)));
		packet += 2;
		/* Register the query in json array */
		json_object_array_add(queries, query);
		query_cpt++;
	}

	json_object_object_add(jparent, "DNS_transaction_id", json_object_new_int((int)transaction_id));

	json_bool is_reponse = FALSE;
	if( response_flag )
		is_reponse = TRUE;
	json_object_object_add(jparent, "DNS_response_flag", json_object_new_boolean(is_reponse));

	json_object_object_add(jparent, "DNS_opcode", json_object_new_int(opcode));
	json_object_object_add(jparent, "DNS_rcode", json_object_new_int((int)reply_code));
	json_object_object_add(jparent, "DNS_error", json_object_new_string(dns_rcodes[reply_code]));
	json_object_object_add(jparent, "DNS_QDCOUNT", json_object_new_int((int)query_count));
	json_object_object_add(jparent, "DNS_ANCOUNT", json_object_new_int((int)answer_count));
	json_object_object_add(jparent, "DNS_NSCOUNT", json_object_new_int((int)authority_count));
	json_object_object_add(jparent, "DNS_ARCOUNT", json_object_new_int((int)additionnal_count));
	json_object_object_add(jparent, "DNS_Names", queries);

	RETURN_DATA_AFTER((int)(packet-svg_packet));
}
