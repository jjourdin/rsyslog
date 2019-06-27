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

static inline int initBuffer(StreamBuffer *sb) {
    DBGPRINTF("initBuffer\n");

    sb->buffer = calloc(1, DEFAULT_BUFF_START_SIZE);

    if(sb->buffer) {
        sb->bufferSize = DEFAULT_BUFF_START_SIZE;
        return 0;
    }

    return -1;
}

void *streamBufferCreate(void *object) {
    DBGPRINTF("streamBufferCreate\n");

    StreamBuffer *sb = calloc(1, sizeof(StreamBuffer));
    if(sb) {
        if(initBuffer(sb) == 0) {
            sb->object = object;
            return (void *)sb;
        }

        free(sb);
    }

    return NULL;
}

void *streamBufferDelete(void *object) {
    DBGPRINTF("streamBufferDelete\n");

    if(object) {
        StreamBuffer *sb = (StreamBuffer *)object;

        if(sb->bufferDump) {
            streamBufferDumpToFile(sb);
            deleteFileStruct(sb->bufferDump);
        }

        if(sb->buffer) free(sb->buffer);
        if(sb->ruleList) yaraDeleteRuleList(sb->ruleList);

        free(sb);
    }
}

void streamInitConfig(StreamsCnf *conf) {
    DBGPRINTF("streamInitConfig\n");
    memset(conf, 0, sizeof(StreamsCnf));

    conf->sbPool = createPool(streamBufferCreate, streamBufferDelete);

    streamsCnf = conf;
    return;
}

void streamDeleteConfig(StreamsCnf *conf) {
    DBGPRINTF("streamDeleteConfig\n");

    if(conf->streamStoreFolder) free(conf->streamStoreFolder);
    destroyPool(conf->sbPool);
    free(conf);
}

int linkStreamBufferToDumpFile(StreamBuffer *sb, char *filename) {
    DBGPRINTF("linkStreamBufferToDumpFile\n");

    if(streamsCnf->streamStoreFolder) {
        DBGPRINTF("linking file '%s' to stream buffer\n", filename);
        FILE *opened = openFile(streamsCnf->streamStoreFolder, filename);
        if(!opened) return -1;

        sb->bufferDump = createFileStruct();

        strncpy(sb->bufferDump->filename, filename, 256);
        strncpy(sb->bufferDump->directory, streamsCnf->streamStoreFolder, 2048);
        sb->bufferDump->pFile = opened;
    }
    return 0;
}

uint32_t streamBufferDumpToFile(StreamBuffer *sb) {
    DBGPRINTF("streamBufferDumpToFile\n");
    uint32_t writeAmount = 0;

    if(sb->bufferDump->pFile) {
        addDataToFile((char *)(sb->buffer), sb->bufferFill, sb->streamOffset, sb->bufferDump);
        writeAmount += sb->bufferFill;
    }

    return writeAmount;
}

int streamBufferExtend(StreamBuffer *sb, uint32_t extLength) {
    DBGPRINTF("streamBufferExtend: extLength=%u\n", extLength);

    if(sb) {
        sb->buffer = realloc(sb->buffer, sb->bufferSize + extLength);
        if(sb->buffer) {
            sb->bufferSize += extLength;
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

static inline void streamBufferShift(StreamBuffer *sb, int amount) {
    DBGPRINTF("streamBufferShift, amount=%u\n", amount);

    if(sb) {
        if(amount > sb->bufferSize) amount = sb->bufferSize;
        if(sb->bufferDump) addDataToFile(sb->buffer, amount, sb->streamOffset, sb->bufferDump);
        memmove(sb->buffer, sb->buffer + amount, sb->bufferFill - amount);
        sb->bufferFill -= amount;
        sb->streamOffset += amount;
    }
    else {
        DBGPRINTF("streamBufferShift: ERROR trying to shift StreamBuffer, but object is NULL\n");
    }
    return;
}

/**
 * The data given at this point SHOULD BE the next immediate data for the stream
 * @param sb
 * @param dataLength
 * @param data
 * @return
 */
int streamBufferAddDataSegment(StreamBuffer *sb, uint32_t dataLength, uint8_t *data) {
    DBGPRINTF("streamBufferAddDataSegment, dataLength: %u\n", dataLength);

    if(sb) {
        if(dataLength > streamsCnf->streamMaxBufferSize) {
            DBGPRINTF("dataLength is too high (%u)for buffer and its max size, "
                      "capping at %u\n", dataLength, streamsCnf->streamMaxBufferSize);
            dataLength = streamsCnf->streamMaxBufferSize;
        }
        // extend buffer if not big enough
        if(sb->bufferFill + dataLength > sb->bufferSize) {
            uint32_t addition = sb->bufferFill + dataLength - sb->bufferSize;
            if(sb->bufferSize + addition <= streamsCnf->streamMaxBufferSize) {
                streamBufferExtend(sb, addition);
            }
            else if(sb->bufferSize < streamsCnf->streamMaxBufferSize) {
                uint32_t extension = streamsCnf->streamMaxBufferSize - sb->bufferSize;
                streamBufferExtend(sb, extension);
                streamBufferShift(sb, addition - extension);
            }
            else {
                streamBufferShift(sb, addition);
            }
        }
        memcpy(sb->buffer + sb->bufferFill, data, dataLength);
        sb->bufferFill += dataLength;

        return 0;
    }

    return 1;
}

void printStreamBufferInfo(StreamBuffer *sb) {
    DBGPRINTF("\n\n########## SB INFO ##########\n");

    DBGPRINTF("sb->bufferSize: %u\n", sb->bufferSize);
    DBGPRINTF("sb->bufferFill: %u\n", sb->bufferFill);
    DBGPRINTF("sb->streamOffset: %u\n", sb->streamOffset);

    DBGPRINTF("\n\n########## END SB INFO ##########\n");
    return;
}
