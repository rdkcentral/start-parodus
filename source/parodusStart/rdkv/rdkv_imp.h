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
 * @file rdkv_imp.h
 *
 * @description RDKV specific parodusStart implementation.
 *
 */

#ifndef RDKV_IMP_H
#define RDKV_IMP_H

#include <stdio.h>
#include "../start_parodus.h"

#define RDKV_LOG_ERROR 0
#define RDKV_LOG_INFO  1

/**
 * @brief Logs a formatted message to stdout (info) or stderr (error).
 */
void rdkv_log(int level, const char *msg, ...);

#define LogInfo(...)  rdkv_log(RDKV_LOG_INFO, __VA_ARGS__)
#define LogError(...) rdkv_log(RDKV_LOG_ERROR, __VA_ARGS__)

#endif /* RDKV_IMP_H */
