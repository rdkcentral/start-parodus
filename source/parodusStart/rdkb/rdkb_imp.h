/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/**
 * @file rdkb_imp.h
 *
 * @description RDKB specific parodusStart log initialization.
 *
 */

#ifndef RDKB_IMP_H
#define RDKB_IMP_H

#include <stdio.h>
#include "../start_parodus.h"

/* stderr redirect target set by log_init(), shared across the app */
extern FILE *g_fArmConsoleLog;

#define RDKB_LOG_ERROR 0
#define RDKB_LOG_INFO  1

/**
 * @brief Logs a formatted message to g_fArmConsoleLog (or stdout if unset).
 */
void rdkb_log(int level, const char *msg, ...);

#define LogInfo(...)  rdkb_log(RDKB_LOG_INFO, __VA_ARGS__)
#define LogError(...) rdkb_log(RDKB_LOG_ERROR, __VA_ARGS__)

char *getWebpaUrl(const char *buildType);
