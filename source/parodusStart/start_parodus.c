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
 * @file start_parodus.c
 *
 * @description This is a C application to start parodus process.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#if !(_COSA_BCM_MIPS_ || _COSA_DRG_TPG_ || CONFIG_CISCO)
#include <autoconf.h>
#endif
#include "start_parodus.h"
#ifdef RDKV
#include "rdkv/rdkv_imp.h"
#include <signal.h>
#else
#include "rdkb/rdkb_imp.h"
#endif

#define MAX_SERVER_URL_SIZE           64
#define MAX_BUILD_LEN                 16
#define MAX_PARTNERID_LEN             64

// RDKB uses breakpad for crash handling; RDKV uses the custom signal handler below.
#ifndef RDKV
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#else
static void processExit(int sig)
{
    printf("Process Exit handling %d\n", sig);
}
#endif

#ifndef UNIT_TEST_DOCKER_SUPPORT
    #define STATIC                    static

#else
        #define STATIC

    extern FILE* fopen_mock(const char* filename, const char* mode);
    #define fopen                     fopen_mock    // Mock fopen for testing

#endif

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
STATIC char *TOKEN_SERVER_URL = NULL;
STATIC char *DNS_TEXT_URL = NULL;

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

#ifndef UNIT_TEST_DOCKER_SUPPORT
int main(int argc, char *argv[])
{
#ifndef RDKV
#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#endif
#else
    signal(SIGTERM, processExit);
    signal(SIGKILL, processExit);
    signal(SIGABRT, processExit);
#endif

    /*Log init*/
    log_init();

    if (handle_wan_status(argc, argv))
    {
                return 0;
    }

    /*Coverity Fix CID:78992,78513  */
    char modelName[256]={'\0'};
    char serialNumber[256]={'\0'};
    char firmwareVersion[64]={'\0'};
    char deviceMac[64]={'\0'};
    char webpaInterface[64]={"erouter0"};
    char manufacturer[64]={'\0'};
    char parodus_url[MAX_SERVER_URL_SIZE] = {'\0'};
    char seshat_url[MAX_SERVER_URL_SIZE] = {'\0'};
    char build_type[MAX_BUILD_LEN] = {'\0'};
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    char *webpaUrl = NULL;
    char command[4096]={'\0'};
    unsigned int bootTime=0;
    int commandPublishStatus = -1;
    int wait_time = 0;
    int jwtFlag;
    int webpaPingTime;
    char final_lastRebootReason[128] = {'\0'};
    char client_cert_path[128]={'\0'};
    char ssl_engine[32]="NA";
    char ssl_cert_type[8]="NA";
    char ssl_reference_name[128]="NA";
    int decodeStatus = -1;
    ParodusCommandConfig commandConfig;

#if defined (START_PARODUS) && defined (UPDATE_CONFIG_FILE)
    LogInfo("Proceeding to unregister wan-status event\n");

    system("/etc/utopia/registration.d/02_parodus stop");
#endif
    LogInfo("startParodus is enabled\n");

    init_hal_db();
    getModelName(modelName, sizeof(modelName));
    getSerialNumber(serialNumber, sizeof(serialNumber));
    getFirmwareName(firmwareVersion, sizeof(firmwareVersion));
    getManufacturer(manufacturer, sizeof(manufacturer));
    getRebootReason(final_lastRebootReason, sizeof(final_lastRebootReason));

    if (getDeviceMac(deviceMac, sizeof(deviceMac)) != 0)
    {
        return -1;
    }

    getBootTime(&bootTime, &wait_time);

    LogInfo("Fetch parodus url from device.properties file\n");
    get_url(parodus_url, seshat_url, build_type);
    LogInfo("parodus_url returned is %s\n", parodus_url);
    LogInfo("seshat_url returned is %s\n", seshat_url);
    LogInfo("build_type returned is %s\n", build_type);

    if (getPartnerId(partner_id, sizeof(partner_id)) != 0)
    {
        goto RETURN_ERROR;
    }

    if (getWebpaConfig(build_type, partner_id, &webpaUrl,
                            &TOKEN_SERVER_URL, &DNS_TEXT_URL) != 0)
    {
        goto RETURN_ERROR;
    }

    jwtFlag = getAcquireJwt();
    webpaPingTime = getWebpaPingTime();

    decodeStatus = getDeviceConfigFile();

    if (getClientCertPath(decodeStatus, client_cert_path, sizeof(client_cert_path)) != 0)
    {
        goto RETURN_ERROR;
    }

    if (getSslReferenceName(decodeStatus, ssl_reference_name,
                            sizeof(ssl_reference_name)) != 0)
    {
        goto RETURN_ERROR;
    }

    if (getSslEngine(client_cert_path, ssl_engine, sizeof(ssl_engine)) != 0)
    {
        goto RETURN_ERROR;
    }

    if (getSslCertType(ssl_cert_type, sizeof(ssl_cert_type)) != 0)
    {
        goto RETURN_ERROR;
    }

    if (getWebpaInterface(webpaInterface, sizeof(webpaInterface)) != 0)
    {
        goto RETURN_ERROR;
    }
    LogInfo("Framing command for parodus\n");
    commandConfig = (ParodusCommandConfig){
            .modelName = modelName,
            .serialNumber = serialNumber,
            .manufacturer = manufacturer,
            .lastRebootReason = final_lastRebootReason,
            .firmwareVersion = firmwareVersion,
            .bootTime = bootTime,
            .deviceMac = deviceMac,
            .webpaInterface = webpaInterface,
            .webpaUrl = webpaUrl,
            .webpaPingTime = webpaPingTime,
            .parodusUrl = parodus_url,
            .partnerId = partner_id,
            .seshatUrl = seshat_url,
            .clientCertPath = client_cert_path,
            .sslEngine = ssl_engine,
            .sslCertType = ssl_cert_type,
            .sslReferenceName = ssl_reference_name,
            .tokenServerUrl = TOKEN_SERVER_URL,
            .acquireJwt = jwtFlag,
            .dnsTextUrl = DNS_TEXT_URL,
            .bootTimeRetryWait = wait_time
    };

    if (buildParodusCommand(command, sizeof(command), &commandConfig) != 0)
    {
        LogError("Failed to frame parodus command\n");
        goto RETURN_ERROR;
    }

    LogInfo("parodus command formed is: %s\n", command);

    commandPublishStatus = publishParodusCommand(command);
    if(commandPublishStatus == 0)
    {
        LogInfo("Published parodus command\n");
    }
    else
    {
        LogError("Failed to publish parodus command\n");
    }

    if(webpaUrl != NULL)
    {
        free(webpaUrl);
        webpaUrl = NULL;
    }
    syncPsmDbOnUpgrade(firmwareVersion);

    if (startParodusProcess(command) != 0)
    {
        LogError("Failed to start parodus process\n");
    }

    log_close();
    return 0;

RETURN_ERROR:
    if(webpaUrl != NULL)
    {
        free(webpaUrl);
        webpaUrl = NULL;
    }
    LogError("main function - RETURN_ERROR\n");
    return -1;

}
#endif // UNIT_TEST_DOCKER_SUPPORT