/* stream_buffer.h
 *
 * This header contains the definition of stream buffers
 *
 * File begun on 2019-20-05
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

#ifndef STREAM_BUFFER_H
#define STREAM_BUFFER_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rsyslog.h"

#define DEFAULT_BUFF_START_SIZE     4096
#define BUFF_ADD_BLOCK_SIZE         4096

typedef struct StreamBufferSegment_ {
    uint32_t length;
    uint32_t streamOffset;
    struct StreamBufferSegment_ *next;
} StreamBufferSegment;

typedef struct StreamBuffer_ {
    uint8_t *buffer;
    uint32_t bufferSize;
    uint32_t bufferFill;

    struct YaraRuleList_ *ruleList;

    uint32_t sbsNumber;
    StreamBufferSegment *sbsList;
} StreamBuffer;


StreamBuffer *streamBufferCreate();
int streamBufferExtend(StreamBuffer *, uint32_t);
void streamBufferDelete(StreamBuffer *);
int streamBufferAddDataSegment(StreamBuffer *, uint32_t, uint32_t, uint8_t *);
void printStreamBufferInfo(StreamBuffer *);
void printStreamBufferSegmentInfo(StreamBufferSegment *);

#endif /* STREAM_BUFFER_H */
