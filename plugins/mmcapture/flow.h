/* flow.h
 *
 * This file contains structures and prototypes of functions used
 * for flow handling.
 *
 * File begun on 2019-05-15
 *
 * Created by:
 *  - Théo Bertin (theo.bertin@advens.fr)
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

#include "packets.h"

#ifndef FLOW_H
#define FLOW_H

/* clear the address structure by setting all fields to 0 */
#define FLOW_CLEAR_ADDR(a) do {  \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* FlowHash is just an uint32_t */
typedef uint32_t FlowHash;

typedef struct FlowAddress_ {
    union {
        uint32_t       address_un_data32[4]; /* type-specific field */
        uint16_t       address_un_data16[8]; /* type-specific field */
        uint8_t        address_un_data8[16]; /* type-specific field */
    } address;
} FlowAddress;

/* Hash key for the flow hash */
typedef struct FlowHashKey4_
{
    union {
        struct {
            uint32_t addrs[2];
            uint16_t ports[2];
            uint32_t proto;
        };
        const uint32_t u32[4];
    };
} FlowHashKey4;

typedef struct FlowHashKey6_
{
    union {
        struct {
            uint32_t addrs[8];
            uint16_t ports[2];
            uint32_t proto;
        };
        const uint32_t u32[4];
    };
} FlowHashKey6;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8

typedef struct Flow_ {
    FlowAddress src, dst;
    uint16_t sp, dp;

    uint8_t proto;
    uint16_t vlanId;

    uint32_t flowHash;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t todstbytecnt;
    uint64_t tosrcbytecnt;
} Flow;

#endif /* FLOW_H */
