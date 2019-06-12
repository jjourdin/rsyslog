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

StreamsCnf *streamsCnf;

static inline void addBufferToConfList(StreamBuffer *buffer) {
    DBGPRINTF("addBufferToConfList\n");

    if(streamsCnf->listHead) {
        buffer->next = streamsCnf->listHead;
        streamsCnf->listHead->prev = buffer;
        buffer->prev = NULL;
    }
    else {
        buffer->next = NULL;
        buffer->prev = NULL;
    }
    streamsCnf->listHead = buffer;
    streamsCnf->streamNumber++;
    return;
}

static inline void removeBufferFromConfList(StreamBuffer *buffer) {
    DBGPRINTF("removeBufferFromConfList\n");

    if(buffer->prev) buffer->prev->next = buffer->next;
    if(buffer->next) buffer->next->prev = buffer->prev;
    if(streamsCnf->listHead == buffer) streamsCnf->listHead = buffer->next;
    streamsCnf->streamNumber--;
}

static inline int initBuffer(StreamBuffer *sb) {
    DBGPRINTF("initBuffer\n");

    sb->buffer = calloc(1, DEFAULT_BUFF_START_SIZE);

    if(sb->buffer) {
        sb->bufferSize = DEFAULT_BUFF_START_SIZE;
        return 0;
    }

    return -1;
}

void streamInitConfig(StreamsCnf *conf) {
    DBGPRINTF("streamInitConfig\n");
    memset(conf, 0, sizeof(StreamsCnf));

    conf->streamStoreFolder = malloc(256);
    strncpy(conf->streamStoreFolder, "/var/log/rsyslog/mmcapture-streams/", 256);

    streamsCnf = conf;
    return;
}

void streamDeleteConfig(StreamsCnf *conf) {
    DBGPRINTF("streamDeleteConfig\n");

    StreamBuffer *delete, *sb = streamsCnf->listHead;
    while(sb) {
        delete = sb;
        sb = sb->next;
        streamBufferDelete(delete);
    }
    if(conf->streamStoreFolder) free(conf->streamStoreFolder);
    free(conf);
}

int linkStreamBufferToDumpFile(StreamBuffer *sb, char *filename) {
    DBGPRINTF("linkStreamBufferToDumpFile\n");

    if(streamsCnf->streamStoreFolder) {
        DBGPRINTF("linking file '%s' to stream buffer\n", filename);
        FILE *opened = openFile(streamsCnf->streamStoreFolder, filename);
        if(!opened) return -1;

        strncpy(sb->bufferDump->fileFullPath, filename, 256);
        sb->bufferDump->pFile = opened;
    }
    return 0;
}

uint32_t streamBufferDumpToFile(StreamBuffer *sb) {
    DBGPRINTF("streamBufferDumpToFile\n");
    uint32_t writeAmount = 0;

    if(sb->bufferDump) {
        StreamBufferSegment *sbs = sb->sbsList;
        while(sbs) {
            addDataToFile((char *)(sb->buffer + sbs->streamOffset), sbs->length, sbs->streamOffset, sb->bufferDump);
            writeAmount += sbs->length;
            sbs = sbs->next;
        }
    }

    return writeAmount;
}

StreamBuffer *streamBufferCreate() {
    DBGPRINTF("streamBufferCreate\n");

    StreamBuffer *sb = calloc(1, sizeof(StreamBuffer));
    if(sb) {
        sb->bufferDump = createFileStruct();
        if(initBuffer(sb) == 0 && sb->bufferDump) {
            addBufferToConfList(sb);
            return sb;
        }

        free(sb);
    }

    return NULL;
}

void streamBufferDelete(StreamBuffer *sb) {
    DBGPRINTF("streamBufferDelete\n");

    if(sb) {
        removeBufferFromConfList(sb);

        deleteFileStruct(sb->bufferDump);

        if(sb->buffer) free(sb->buffer);
        if(sb->ruleList) yaraDeleteRuleList(sb->ruleList);

        StreamBufferSegment *sbsFree, *sbs = sb->sbsList;
        while(sbs) {
            sbsFree = sbs;
            sbs = sbs->next;
            free(sbsFree);
        }
        free(sb);
    }
}

int streamBufferExtend(StreamBuffer *sb, uint32_t extLength) {
    DBGPRINTF("streamBufferExtend\n");

    if(sb) {
        uint8_t i = 0;
        uint32_t trueExtLength = 0;
        do {
            trueExtLength = ++i*BUFF_ADD_BLOCK_SIZE;
        }while((trueExtLength) < extLength);

        sb->buffer = realloc(sb->buffer, sb->bufferSize + trueExtLength);
        if(sb->buffer) {
            sb->bufferSize += trueExtLength;
            return 0;
        }
        else {
            DBGPRINTF("error while extending stream buffer\n");
        }
    }
    else {
        return 0;
    }

    return -1;
}

int streamBufferAddDataSegment(StreamBuffer *sb, uint32_t offset, uint32_t dataLength, uint8_t *data) {
    DBGPRINTF("streamBufferAddDataSegment offset: %u, dataLength: %u\n", offset, dataLength);

    if(sb) {
        uint32_t bufferSize = sb->bufferSize;

        // extend buffer if not big enough
        if(offset+dataLength > bufferSize) {
            streamBufferExtend(sb, (offset+dataLength)-bufferSize);
        }

        // add data to buffer
        memmove(sb->buffer + offset, data, dataLength);
        sb->bufferFill = (offset+dataLength > sb->bufferFill) ? offset+dataLength : sb->bufferFill;

        StreamBufferSegment *sbs = calloc(1, sizeof(StreamBufferSegment));
        sbs->streamOffset = offset;
        sbs->length = dataLength;

        sbs->next = sb->sbsList;
        sb->sbsList = sbs;
        sb->sbsNumber++;

        return 0;
    }

    return 1;
}

void printStreamBufferInfo(StreamBuffer *sb) {
    DBGPRINTF("\n\n########## SB INFO ##########\n");

    DBGPRINTF("sb->bufferSize: %u\n", sb->bufferSize);
    DBGPRINTF("sb->bufferFill: %u\n", sb->bufferFill);
    DBGPRINTF("sb->sbsNumber: %u\n", sb->sbsNumber);
    if(sb->sbsList) {
        printStreamBufferSegmentInfo(sb->sbsList);
    }

    DBGPRINTF("\n\n########## END SB INFO ##########\n");
    return;
}

void printStreamBufferSegmentInfo(StreamBufferSegment *sbs) {
    DBGPRINTF("\n\n########## SBS INFO ##########\n");

    DBGPRINTF("sbs->length: %u\n", sbs->length);
    DBGPRINTF("sbs->offset: %u\n", sbs->streamOffset);

    if(sbs->next) {
        printStreamBufferSegmentInfo(sbs->next);
    }

    DBGPRINTF("\n\n########## END SBS INFO ##########\n");
    return;
}