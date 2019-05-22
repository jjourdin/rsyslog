/* stream_buffer.c
 *
 * This file contains functions to bufferize streams
 *
 * File begun on 2019-20-5
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

#include "stream_buffer.h"

static inline int initBuffer(StreamBuffer *sb) {
    sb->buffer = calloc(1, DEFAULT_BUFF_START_SIZE);

    if(sb->buffer) {
        sb->bufferSize = DEFAULT_BUFF_START_SIZE;
        return 0;
    }

    return -1;
}

StreamBuffer *streamBufferCreate() {
    DBGPRINTF("streamBufferCreate\n");

    StreamBuffer *sb = calloc(1, sizeof(StreamBuffer));
    if(sb) {
        if(initBuffer(sb) == 0) {
            return sb;
        }

        free(sb);
    }

    return NULL;
}

void streamBufferDelete(StreamBuffer *sb) {
    if(sb) {
        if(sb->buffer) {
            free(sb->buffer);
        }
        free(sb);
    }
}

int streamBufferExtend(StreamBuffer *sb, uint32_t extLength) {
    DBGPRINTF("streamBufferExtend\n");

    if(sb) {
        uint8_t i = 0;
        do {
            i++;
        }while((i*BUFF_ADD_BLOCK_SIZE) < extLength);

        sb->buffer = realloc(sb->buffer, sb->bufferSize + i*BUFF_ADD_BLOCK_SIZE);
        if(sb->buffer) {
            sb->bufferSize += extLength;
            return 0;
        }
        else {
            DBGPRINTF("error while extending stream buffer\n")
        }
    }
    else {
        return 0;
    }

    return -1;
}

int streamBufferAddDataAtSegment(StreamBufferSegment *sbs, uint8_t *data) {
    DBGPRINTF("streamBufferAddDataAtSegment\n");

    if(sbs) {
        if(sbs->streamBuffer) {
            uint32_t offset = sbs->streamOffset;
            uint32_t dataLength = sbs->length;
            uint32_t bufferSize = sbs->streamBuffer->bufferSize;

            // extend buffer if not big enough
            if(offset+dataLength > bufferSize) {
                streamBufferExtend(sbs->streamBuffer, (offset+dataLength)-bufferSize);
            }

            memmove(sbs->streamBuffer->buffer + offset, data, dataLength);

            return 0;
        }
    }

    return 1;
}