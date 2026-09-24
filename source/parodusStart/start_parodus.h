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

#ifndef START_PARODUS_H
#define START_PARODUS_H

#include <stddef.h>
#include <stdio.h>

#include "parodus_command.h"

FILE *log_init(void);
void log_close(void);
int handle_wan_status(int argc, char *argv[]);
void init_hal_db(void);

int publishParodusCommand(const char *command);
int startParodusProcess(const char *command);
int buildParodusCommand(char *command, size_t commandLen,
                        const ParodusCommandConfig *config);

void get_url(char *parodusUrl, char *seshatUrl, char *buildType);
int getDeviceMac(char *deviceMac, size_t macLen);
int getPartnerId(char *partnerId, size_t partnerIdLen);
int getWebpaConfig(const char *buildType, const char *partnerId, char **webpaUrl,
                   char **tokenServerUrl, char **dnsTextUrl);
int getAcquireJwt(void);
int getWebpaPingTime(void);
int getDeviceConfigFile(void);
int getClientCertPath(int decodeStatus, char *clientCertPath, size_t pathLen);
int getSslReferenceName(int decodeStatus, char *referenceName, size_t referenceLen);
int getSslEngine(const char *clientCertPath, char *sslEngine, size_t engineLen);
int getSslCertType(char *certType, size_t certTypeLen);
int getWebpaInterface(char *interfaceName, size_t interfaceLen);
void getBootTime(unsigned int *bootTime, int *waitTime);
void getModelName(char *modelName, size_t len);
void getSerialNumber(char *serialNumber, size_t len);
void getFirmwareName(char *fwName, size_t fwNameLen);
void getManufacturer(char *manufacturer, size_t len);
void getRebootReason(char *reason, size_t reasonLen);
int syncPsmDbOnUpgrade(char *firmwareVersion);

#endif /* START_PARODUS_H */