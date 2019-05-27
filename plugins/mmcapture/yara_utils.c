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

int yaraInit() {
    if(yr_initialize()) {
        DBGPRINTF("YARA: could not initialize yara module\n");
        return -1;
    }

    yaraGlobalConf = calloc(1, sizeof(YaraConf));
    if(yr_compiler_create(&yaraGlobalConf->compiler)) {
        DBGPRINTF("YARA: could not create compiler, insufficient memory\n");
        return -1;
    }
    yr_compiler_set_callback(yaraGlobalConf->compiler, yaraErrorCallback(), NULL);

    return 0;
}

int yaraFin() {
    if(yr_finalize()) {
        DBGPRINTF("YARA: could not finalize yara module\n");
        return -1;
    }

    if(yaraGlobalConf->compiler) {
        yr_compiler_destroy(yaraGlobalConf->compiler);
    }

    return 0;
}

int yaraAddRuleFile(FILE *file, const char *namespace, const char *fileName) {
    int errNum;
    if(yaraGlobalConf) {
        errNum = yr_compiler_add_file(yaraGlobalConf->compiler, file, namespace, fileName)
        if(errNum) {
            if(fileName)    DBGPRINTF("YARA: found %d errors while compiling a file\n", errNum);
            else            DBGPRINTF("YARA: found %d errors while compiling file '%s'\n", errNum, fileName);
        }
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
    switch(message) {
        case CALLBACK_MSG_RULE_MATCHING:
            YR_RULE *rule = (YR_RULE*) messageData;
            DBGPRINTF("YARA SCAN: rule match -> rule '%s'\n", rule->identifier);
            break;
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            break;
        case CALLBACK_MSG_SCAN_FINISHED:
            break;
        case CALLBACK_MSG_IMPORT_MODULE:
            YR_MODULE_IMPORT *import = (YR_MODULE_IMPORT*) messageData;
            DBGPRINTF("YARA IMPORT: importing module '%s'\n", import->module_name);
            break;
        case CALLBACK_MSG_MODULE_IMPORTED:
            DBGPRINTF("YARA IMPORT: module imported\n");
    }

    return CALLBACK_CONTINUE;
}