/* yara_utils.h
 *
 * This header contains prototypes for yara_utils.c,
 * being functions to manage yara API
 *
 * File begun on 2018-27-5
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

#include <yara.h>
#include <pthread.h>
#include <time.h>
#include "rsyslog.h"

#ifndef YARA_UTILS_H
#define YARA_UTILS_H

typedef struct YaraCnf_ {
    uint8_t status;
#define YARA_CNF_NONE 0x00
#define YARA_CNF_INIT 0x01
#define YARA_CNF_RULES_ADDED 0x02
#define YARA_CNF_RULES_COMPILED 0x04

    YR_COMPILER *compiler;
    YR_RULES    *rules;

    char *rulesDir;
    struct YaraRuleFile_ **fileList;
    uint8_t fileListSize;

    struct YaraStreamQueue_ *queue;
} YaraCnf;

YaraCnf *globalYaraCnf;

typedef struct YaraRuleFile_ {
    char *filename;
    FILE *file;
} YaraRuleFile;

typedef struct YaraStreamQueue_ {
    uint32_t queueSize;
    struct YaraStreamElem_ *head;
    struct YaraStreamElem_ *tail;
} YaraStreamQueue;

typedef struct YaraStreamElem_ {
    uint8_t *buffer;
    uint32_t length;

    uint8_t status;
#define YSE_INIT 0
#define YSE_READY 1
#define YSE_PROCESS 2
#define YSE_FINISHED 4
#define YSE_RULE_MATCHED 8
#define YSE_RULE_NOMATCH 16

    YR_RULE *rule;

    struct YaraStreamElem_ *next;
    struct YaraStreamElem_ *prev;
} YaraStreamElem;

int yaraInit(YaraCnf *);
int yaraFin();
void yaraStreamQueueDestroy(YaraStreamQueue *);
int yaraAddRuleFile(FILE *, const char *, const char *);
int yaraCompileRules();
int yaraScanStreamElem(YaraStreamElem *, int, int);
void yaraErrorCallback(int, const char *, int, const char *, void *);
int yaraScanOrImportCallback(int, void *, void *);

#endif /* YARA_UTILS_H */
