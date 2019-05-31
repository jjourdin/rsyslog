/* yara_utils.c
 *
 *  This file contains functions related to yara API
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

#include "yara_utils.h"

int yaraInit(YaraCnf *conf) {
    if(yr_initialize()) {
        DBGPRINTF("YARA: could not initialize yara module\n");
        return -1;
    }

    conf = calloc(1, sizeof(YaraCnf));
    if(yr_compiler_create(&conf->compiler)) {
        DBGPRINTF("YARA: could not create compiler, insufficient memory\n");
        return -1;
    }
    yr_compiler_set_callback(conf->compiler, yaraErrorCallback, NULL);

    conf->queue = calloc(1, sizeof(YaraStreamQueue));
    if(!conf->queue) {
        DBGPRINTF("YARA error: could not load queue for global yara config\n");
        return -1;
    }

    conf->status |= YARA_CNF_INIT;
    globalYaraCnf = conf;
    return 0;
}

int yaraFin() {
    if(yr_finalize()) {
        DBGPRINTF("YARA: could not finalize yara module\n");
        return -1;
    }

    if(globalYaraCnf->compiler) {
        yr_compiler_destroy(globalYaraCnf->compiler);
    }
    if(globalYaraCnf->rules) {
        yr_rules_destroy(globalYaraCnf->rules);
    }
    if(globalYaraCnf->queue) {
        yaraStreamQueueDestroy(globalYaraCnf->queue);
    }

    return 0;
}

void yaraStreamQueueDestroy(YaraStreamQueue *queue) {
    YaraStreamElem *queueElem = queue->head;
    YaraStreamElem *destroy;

    while(queueElem) {
        destroy = queueElem;
        queueElem = queueElem->next;
        free(destroy);
    }

    return;
}

int yaraAddRuleFile(FILE *file, const char *namespace, const char *fileName) {
    int errNum;
    if(globalYaraCnf->status & YARA_CNF_INIT) {
        errNum = yr_compiler_add_file(globalYaraCnf->compiler, file, namespace, fileName);
        if(errNum) {
            if(fileName) {
                DBGPRINTF("YARA: found %d errors while compiling a file\n", errNum);
            }
            else {
                DBGPRINTF("YARA: found %d errors while compiling file '%s'\n", errNum, fileName);
            }
            return -1;
        }

        DBGPRINTF("YARA: added file '%s' to compiler\n", fileName);
        globalYaraCnf->status |= YARA_CNF_RULES_ADDED;
        return 0;
    }
    else {
        DBGPRINTF("YARA error: trying to add ruleFile when yara context is not initialised\n");
        return -1;
    }
}

int yaraCompileRules() {
    int errNum;
    if(globalYaraCnf->status & YARA_CNF_RULES_ADDED) {
        errNum = yr_compiler_get_rules(globalYaraCnf->compiler, &globalYaraCnf->rules);
        if(errNum) {
            DBGPRINTF("YARA error: could not compile rules ->insufficient memory\n");
            return -1;
        }
        globalYaraCnf->status |= YARA_CNF_RULES_COMPILED;
        return 0;
    }
    else {
        DBGPRINTF("YARA error: trying to compile rules when no rule was added to compiler\n");
        return -1;
    }
}

int yaraScanStreamElem(YaraStreamElem *elem, int fastMode, int timeout) {
    int errNum;
    struct timespec start, stop;

    if(globalYaraCnf->status & YARA_CNF_RULES_COMPILED && elem->status & YSE_READY) {

        DBGPRINTF("YARA launching scan_mem on %u bytes\n", elem->length);
        clock_gettime(CLOCK_MONOTONIC, &start);
        errNum = yr_rules_scan_mem(
                globalYaraCnf->rules,
                elem->buffer,
                elem->length,
                fastMode ? SCAN_FLAGS_FAST_MODE : 0,
                yaraScanOrImportCallback,
                (void *)elem,
                timeout);
        clock_gettime(CLOCK_MONOTONIC, &stop);

        DBGPRINTF("scanning time: %luus\n", (stop.tv_nsec - start.tv_nsec)/1000);

        if(errNum) {
            switch(errNum) {
                case ERROR_INSUFFICIENT_MEMORY:
                    DBGPRINTF("YARA error: could not scan memory -> insufficient memory\n");
                    return -1;
                case ERROR_TOO_MANY_SCAN_THREADS:
                    DBGPRINTF("YARA error: could not scan memory -> too many scan threads\n");
                    return -1;
                case ERROR_SCAN_TIMEOUT:
                    DBGPRINTF("YARA error: could not scan memory -> timeout reached\n");
                    return -1;
                case ERROR_CALLBACK_ERROR:
                    DBGPRINTF("YARA error: could not scan memory -> callback error\n");
                    return -1;
                case ERROR_TOO_MANY_MATCHES:
                    DBGPRINTF("YARA error: could not scan memory -> too many matches\n");
                    return -1;
                default:
                    DBGPRINTF("YARA error: could not scan memory -> unknown error\n");
                    return -1;
            }
        }

        return 0;
    }
    else {
        DBGPRINTF("YARA error: not scanning memory -> global conf not ready or stream element not ready\n");
        return -1;
    }
}

void yaraErrorCallback(int errorLevel, const char *fileName, int lineNumber, const char *message, void *userData) {
    if(fileName) {
        DBGPRINTF("YARA ERROR[%d]: on file '%s' (line %d) -> %s\n", errorLevel, fileName, lineNumber, message);
    }
    else {
        DBGPRINTF("YARA ERROR[%d]: %s\n", errorLevel, message);
    }

    return;
}

int yaraScanOrImportCallback(int message, void *messageData, void *userData) {
    YR_RULE *rule;
    YR_MODULE_IMPORT *import;
    YaraStreamElem *elem = (YaraStreamElem *)userData;

    if(elem) elem->status |= YSE_FINISHED;

    switch(message) {
        case CALLBACK_MSG_RULE_MATCHING:
            rule = (YR_RULE *)messageData;
            if(elem) {
                elem->status |= YSE_RULE_MATCHED;
                elem->rule = rule;
            }
            DBGPRINTF("YARA SCAN: rule match -> rule '%s'\n", rule->identifier);
            break;
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            if(elem)    elem->status |= YSE_RULE_NOMATCH;
            break;
        case CALLBACK_MSG_SCAN_FINISHED:
            break;
        case CALLBACK_MSG_IMPORT_MODULE:
            import = (YR_MODULE_IMPORT *)messageData;
            DBGPRINTF("YARA IMPORT: importing module '%s'\n", import->module_name);
            break;
        case CALLBACK_MSG_MODULE_IMPORTED:
            DBGPRINTF("YARA IMPORT: module imported\n");
    }

    return CALLBACK_CONTINUE;
}