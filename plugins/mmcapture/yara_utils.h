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

#ifndef YARA_UTILS_H
#define YARA_UTILS_H

typedef struct YaraConf_ {
    YR_COMPILER *compiler;
    YR_RULES    *rules;
} YaraConf;

YaraConf *yaraGlobalConf;

int yaraInit();
int yaraFin();
int yaraAddRuleFile(FILE *, const char *, const char *);
void yaraErrorCallback(int, const char *, int, const char *, void *);
int yaraScanOrImportCallback(int, void *, void *);

#endif /* YARA_UTILS_H */
