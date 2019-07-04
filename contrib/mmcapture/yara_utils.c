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

YaraRuleList *yaraCreateRuleList() {
    YaraRuleList *ruleList = calloc(1, sizeof(YaraRuleList));

    ruleList->list = calloc(RULELIST_DEFAULT_INIT_SIZE, sizeof(YR_RULE *));
    ruleList->size = RULELIST_DEFAULT_INIT_SIZE;

    return ruleList;
}

void yaraDeleteRuleList(YaraRuleList *ruleList) {
    if(ruleList) {
        if(ruleList->list) free(ruleList->list);
        free(ruleList);
    }
    return;
}

void yaraAddRuleToList(YaraRuleList *list, YR_RULE *rule) {
    if(list && rule) {
        if(list->size == list->fill) {
            list->list = (YR_RULE **)realloc((YR_RULE **)list->list, sizeof(YR_RULE *)*(list->size + RULELIST_DEFAULT_INIT_SIZE));
            list->size += RULELIST_DEFAULT_INIT_SIZE;
        }
        list->list[list->fill++] = rule;
    }
    else {
        DBGPRINTF("YARA: could not add rule to list, list or rule is NULL\n");
    }

    return;
}

int yaraIsRuleInList(YaraRuleList *list, YR_RULE *rule) {
    if(list && rule) {
        uint32_t i;
        for(i = 0; i < list->fill; i++) {
            if(strcmp(list->list[i]->identifier, rule->identifier) == 0) {
                return 1;
            }
        }
        return 0;
    }
    else {
        DBGPRINTF("YARA: could not search rule in list, list or rull is NULL\n");
    }
    return 0;
}

int yaraInitConfig(YaraCnf *conf) {
    if(!conf) {
        DBGPRINTF("YARA: invalid yara conf passed\n");
        return -1;
    }

    if(yr_initialize()) {
        DBGPRINTF("YARA: could not initialize yara module\n");
        return -1;
    }

    if(yr_compiler_create(&conf->compiler)) {
        DBGPRINTF("YARA: could not create compiler, insufficient memory\n");
        return -1;
    }
    yr_compiler_set_callback(conf->compiler, yaraErrorCallback, NULL);

    conf->scanMaxSize = SCAN_SIZE_DEFAULT;
    conf->scanType = SCAN_TYPE_DEFAULT;

    conf->status |= YARA_CNF_INIT;
    globalYaraCnf = conf;
    return 0;
}

int yaraDeleteConfig(YaraCnf *conf) {
    if(yr_finalize()) {
        DBGPRINTF("YARA: could not finalize yara module\n");
        return -1;
    }

    if(conf->compiler) {
        yr_compiler_destroy(conf->compiler);
    }
    if(conf->rules) {
        yr_rules_destroy(conf->rules);
    }

    return 0;
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

static inline int yaraScanStreamElem(YaraStreamElem *elem, int fastMode, int timeout) {
    int errNum;
    struct timespec start, stop;

    if(globalYaraCnf->status & YARA_CNF_RULES_COMPILED && elem->status & YSE_READY) {

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

        DBGPRINTF("YARA: scanning time: %luus\n", (stop.tv_nsec - start.tv_nsec)/1000);

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

struct json_object *yaraScan(uint8_t *buffer, uint32_t buffLen, StreamBuffer *sb) {
    YaraStreamElem *elem = calloc(1, sizeof(YaraStreamElem));
    elem->ruleList = yaraCreateRuleList();
    struct json_object *rules = json_object_new_array();
    uint8_t newRules = 0;

    if(globalYaraCnf->scanType == SCAN_PACKET_ONLY) {
        DBGPRINTF("YARA: initializing packet scan\n");
        if(buffer && buffLen) {
            elem->buffer = buffer;
            elem->length = (buffLen > globalYaraCnf->scanMaxSize) ? globalYaraCnf->scanMaxSize : buffLen;
            elem->status |= YSE_READY;
        }
        else {
            DBGPRINTF("YARA: trying to launch packet scan without providing buffer and length\n");
        }
    }
    else {
        DBGPRINTF("YARA: initializing stream scan\n");
        if(sb) {
            pthread_mutex_lock(&(sb->mutex));
            if(globalYaraCnf->scanMaxSize >= sb->bufferFill) {
                elem->buffer = sb->buffer;
                elem->length = sb->bufferFill;
            }
            else {
                DBGPRINTF("YARA: base stream buffer address: %p\n", sb->buffer);
                DBGPRINTF("YARA: stream buffer fill: %u\n", sb->bufferFill);
                elem->buffer = sb->buffer + sb->bufferFill - globalYaraCnf->scanMaxSize - 1;
                elem->length = globalYaraCnf->scanMaxSize;
            }
            elem->status |= YSE_READY;
        }
        else {
            DBGPRINTF("YARA: trying to launch stream scan without providing StreamBuffer\n");
        }
    }

    if(elem->length) {
        if(yaraScanStreamElem(elem, 0, 1)) {
            DBGPRINTF("YARA: error while trying to launch scan\n");
        }
        else if(elem->ruleList->fill) {
            const char *yaraRuleTag;
            uint32_t i;

            DBGPRINTF("YARA: %u element(s) found in scan\n", elem->ruleList->fill);

            if(sb && !sb->ruleList) sb->ruleList = yaraCreateRuleList();

            for(i = 0; i < elem->ruleList->fill; i++) {
                YR_RULE *rule = elem->ruleList->list[i];

                if(globalYaraCnf->scanType == SCAN_STREAM && yaraIsRuleInList(sb->ruleList, rule)) {
                    continue;
                }
                else {
                    struct json_object *ruleJson = json_object_new_object();
                    struct json_object *tagsArrayObject = json_object_new_array();
                    newRules = 1;
                    if(sb)  yaraAddRuleToList(sb->ruleList, rule);
                    json_object_object_add(ruleJson, "rule", json_object_new_string(rule->identifier));

                    yr_rule_tags_foreach(rule, yaraRuleTag)
                    {
                        json_object_array_add(tagsArrayObject, json_object_new_string(yaraRuleTag));
                    }
                    json_object_object_add(ruleJson, "tags", tagsArrayObject);
                    json_object_array_add(rules, ruleJson);
                }
            }
        }
    }
    if(sb) pthread_mutex_unlock(&(sb->mutex));

    yaraDeleteRuleList(elem->ruleList);
    free(elem);
    if(newRules)    return rules;
    else {
        fjson_object_put(rules);
        return NULL;
    }
}

void yaraErrorCallback(int errorLevel, const char *fileName, int lineNumber, const char *message, void *userData) {
    if(fileName) {
        LogError(0, RS_RET_CONFIG_ERROR, "YARA ERROR[%d]: on file '%s' (line %d) -> %s\n", errorLevel, fileName, lineNumber, message);
    }
    else {
        LogError(0, RS_RET_CONFIG_ERROR, "YARA ERROR[%d]: %s\n", errorLevel, message);
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
                if(!yaraIsRuleInList(elem->ruleList, rule))  yaraAddRuleToList(elem->ruleList, rule);
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