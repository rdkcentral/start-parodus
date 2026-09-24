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
 * @file rdkb_imp.c
 *
 * @description RDKB specific parodusStart log initialization.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <limits.h>
#include <ccsp/platform_hal.h>
#include <ccsp/cm_hal.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#if defined(_COSA_BCM_MIPS_)
#include <ccsp/dpoe_hal.h>
#endif
#include "cJSON.h"
#include "safec_lib_common.h"
#include "rdkb_imp.h"

#define DEVICE_PROPS_FILE  "/etc/device.properties"
#define MAX_BUF_SIZE       1024
#define MAX_PROCESS_LEN    16
#define MAX_VALUE_SIZE     64
#define MAX_PARTNERID_LEN  64
#define MAX_SERVER_URL_SIZE 64
#define MAX_BUILD_LEN      16
#define MODULE             "PARODUS"
#define WEBPA_CFG_FILE     "/nvram/webpa_cfg.json"
#define WEBPA_CFG_FIRMWARE_VER "oldFirmwareVersion"
#define ACQUIRE_JWT 1
#define WEBPA_CFG_SERVER_URL "ServerIP"
#define WEBPA_CFG_SERVER_PORT "ServerPort"
#define PSM_PATH_PREFIX     "eRT.com.cisco.spvtg.ccsp.webpa."
#define PSM_COMPONENT_NAME  "com.cisco.spvtg.ccsp.psm"
#define SE_DEVICE_CERT      "/nvram/certs/devicecert_2.pk12"
#define DEVICE_CERT         "/nvram/certs/devicecert_1.pk12"
#define STATIC_CERT         "/etc/ssl/certs/staticXpkiCrt.pk12"
#define PARODUS_UPSTREAM    "tcp://127.0.0.1:6666"
#define SSL_CERT_BUNDLE     "/etc/ssl/certs/ca-certificates.crt"
#define JWT_KEY             "/etc/ssl/certs/webpa-rs256.pem"
#define CRUD_CONFIG_FILE    "/nvram/parodus_cfg.json"
#define PARCONNHEALTH_FILE  "/tmp/parconnhealth.txt"
#define RECORD_JWT_PAYLOAD_FILE "/tmp/xmidt-jwt-payload.json"
#define MAX_QUEUE_SIZE      10

#if !defined(_COSA_BCM_MIPS_)
int s_sysevent_connect(token_t *out_se_token);
#endif

#if defined(_COSA_QCA_ARM_)
#define CONFIG_VENDOR_NAME  "QTI"
#endif

#ifdef CONFIG_CISCO
#define CONFIG_VENDOR_NAME  "Cisco"
#endif

#if (_COSA_BCM_MIPS_ || _COSA_DRG_TPG_)
#define CONFIG_VENDOR_NAME "ARRIS Group, Inc."
#endif

FILE *g_fArmConsoleLog = NULL;
static char parodusStart_Log[MAX_BUF_SIZE] = {'\0'};

static int sync_get_psm_values(char *names[], char *values[], int count);

void rdkb_log(int level, const char *msg, ...)
{
    static const char *_level[] = { "Error", "Info" };
    va_list arg_ptr;
    int nbytes;
    char buf[MAX_BUF_SIZE];
    char curtime[128];
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(curtime, sizeof(curtime), "%y%m%d-%T", timeinfo);

    va_start(arg_ptr, msg);
    nbytes = vsnprintf(buf, sizeof(buf), msg, arg_ptr);
    va_end(arg_ptr);

    if (nbytes >= (int)sizeof(buf))
    {
        buf[sizeof(buf) - 1] = '\0';
    }
    else if (nbytes >= 0)
    {
        buf[nbytes] = '\0';
    }

    if (NULL != g_fArmConsoleLog)
    {
        fprintf(stderr, "%s : [mod=%s, lvl=%s] %s", curtime, MODULE, _level[level], buf);
    }
    else
    {
        fprintf(stdout, "%s : [mod=%s, lvl=%s] %s", curtime, MODULE, _level[level], buf);
    }
}

FILE *log_init(void)
{
    FILE *fp = fopen(DEVICE_PROPS_FILE, "r");
    errno_t rc = -1;

    if (NULL != fp)
    {
        char str[255] = {'\0'};
        while(fscanf(fp,"%254s", str) != EOF)
        {
            char *value = NULL;

            if((value = strstr(str, "PARODUS_START_LOG_FILE=")))
            {
                value = value + strlen("PARODUS_START_LOG_FILE=");
                rc = strcpy_s(parodusStart_Log, MAX_BUF_SIZE, value);
                if(rc != EOK)
                {
                    ERR_CHK(rc);
                    fclose(fp);
                    return NULL;
                }
            }
        }
        fclose(fp);
    }

    g_fArmConsoleLog = freopen(parodusStart_Log, "a+", stderr);
    if (NULL == g_fArmConsoleLog)
    {
        LogError("Error while opening Log file:%s\n", parodusStart_Log);
    }
    else
    {
        LogInfo("Successful in opening parodusStart_Log file:%s\n", parodusStart_Log);
    }
    return g_fArmConsoleLog;
}

void log_close(void)
{
    if (NULL != g_fArmConsoleLog)
    {
        fclose(g_fArmConsoleLog);
        g_fArmConsoleLog = NULL;
    }
}

int handle_wan_status(int argc, char *argv[])
{
    char output[MAX_PROCESS_LEN] = {'\0'};
    FILE *cmd = NULL;
    const char *pid_cmd = "pidof parodus";
    errno_t rc = -1;
    int ind = -1;
    int Wan_Status_Started = 0;

    if((argc > 1) && (NULL != argv[1]))
    {
        rc = strcmp_s("wan-status",strlen("wan-status"),argv[1],&ind);
        ERR_CHK(rc);
        if((!ind) && (rc == EOK))
        {
            if(NULL != argv[2])
            {
                LogInfo("wan-status event received with state %s\n", argv[2]);
                rc = strcmp_s("started",strlen("started"),argv[2],&ind);
                ERR_CHK(rc);
                if((!ind) && (rc == EOK))
                {
                    Wan_Status_Started = 1;
                }
            }
            if (Wan_Status_Started)
            {
                LogInfo("wan-status is ready. Proceed with parodus start up\n");
                if ((cmd = popen(pid_cmd, "r")) == NULL)
                {
                    LogError("Error in getting parodus pid \n");
                    return 1;
                }

                if(fgets(output,MAX_PROCESS_LEN,cmd) == NULL)
                    LogError("fgets() error\n");
                pid_t pid = strtoul(output,NULL,10);// base 10 (decimal)
                LogInfo("Check parodus pid %d\n",pid);
                pclose(cmd);
                if(pid)
                {
                    LogError("wan-status is ready, but Pardous process is already started/running \n");
                    return 1;
                }
            }
            else
            {
                LogInfo("wan-status is not ready , waiting to start parodus..\n");
                log_close();
                return 1;
            }
        }
    }
    return 0;
}

void init_hal_db(void)
{
    if (platform_hal_PandMDBInit() == 0)
    {
        LogInfo("PandMDB initiated successfully\n");
    }
    else
    {
        LogError("Failed to initiate DB\n");
    }

    if (cm_hal_InitDB() == 0)
    {
        LogInfo("cm_hal DB initiated successfully\n");
    }
    else
    {
        LogError("Failed to initiate cm_hal DB\n");
    }
}

int publishParodusCommand(const char *command)
{
    FILE *file;
    int writeStatus;
    int closeStatus;

    if (command == NULL)
    {
        LogError("Invalid parodus command\n");
        return -1;
    }

    LogInfo("Opening parodusCmd file for writing the content\n");
    file = fopen("/tmp/parodusCmd.cmd", "w");
    if (file == NULL)
    {
        LogError("Cannot open %s in write mode\n", "/tmp/parodusCmd.cmd");
        return -1;
    }

    writeStatus = fprintf(file, "%s", command);
    closeStatus = fclose(file);
    if (writeStatus < 0 || closeStatus != 0)
    {
        LogError("Failed to write parodus command\n");
        return -1;
    }

    return 0;
}

int startParodusProcess(const char *command)
{
#ifdef START_PARODUS
    if (command == NULL)
    {
        LogError("Invalid parodus command\n");
        return -1;
    }

    LogInfo("Starting parodus process ..\n");
    return system(command);
#else
    (void)command;
    return 0;
#endif
}

static const char *commandValueOrEmpty(const char *value)
{
    return value != NULL ? value : "";
}

static int appendParodusCommand(char *command, size_t commandLen, size_t *offset,
                                const char *format, ...)
{
    va_list arguments;
    int written;

    if (*offset >= commandLen)
    {
        return -1;
    }

    va_start(arguments, format);
    written = vsnprintf(command + *offset, commandLen - *offset, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= commandLen - *offset)
    {
        return -1;
    }

    *offset += (size_t)written;
    return 0;
}

int buildParodusCommand(char *command, size_t commandLen,
                        const ParodusCommandConfig *config)
{
    size_t offset = 0;

    if (command == NULL || commandLen == 0 || config == NULL)
    {
        return -1;
    }
    command[0] = '\0';

    if (appendParodusCommand(command, commandLen, &offset,
                             "/usr/bin/parodus --hw-model=\"%s\" --hw-serial-number=%s "
                             "--hw-manufacturer=\"%s\" --hw-last-reboot-reason=\"%s\" "
                             "--fw-name=%s --boot-time=%u --hw-mac=%s --webpa-ping-time=%d "
                             "--webpa-interface-used=%s --webpa-url=%s --webpa-backoff-max=8 "
                             "--parodus-local-url=%s --partner-id=%s --ssl-cert-path=%s "
                             "--connection-health-file=%s",
                             commandValueOrEmpty(config->modelName),
                             commandValueOrEmpty(config->serialNumber),
                             commandValueOrEmpty(config->manufacturer),
                             commandValueOrEmpty(config->lastRebootReason),
                             commandValueOrEmpty(config->firmwareVersion), config->bootTime,
                             commandValueOrEmpty(config->deviceMac), config->webpaPingTime,
                             commandValueOrEmpty(config->webpaInterface),
                             commandValueOrEmpty(config->webpaUrl),
                             config->parodusUrl != NULL && config->parodusUrl[0] != '\0'
                                 ? config->parodusUrl : PARODUS_UPSTREAM,
                             commandValueOrEmpty(config->partnerId), SSL_CERT_BUNDLE,
                             PARCONNHEALTH_FILE) != 0)
    {
        return -1;
    }

#ifdef ENABLE_SESHAT
    if (appendParodusCommand(command, commandLen, &offset, " --seshat-url=%s",
                             commandValueOrEmpty(config->seshatUrl)) != 0)
    {
        return -1;
    }
#endif

    if (appendParodusCommand(command, commandLen, &offset,
                             " --client-cert-path=%s --ssl-engine=%s --ssl-cert-type=%s "
                             "--ssl-reference-name=%s --token-server-url=%s",
                             commandValueOrEmpty(config->clientCertPath),
                             commandValueOrEmpty(config->sslEngine),
                             commandValueOrEmpty(config->sslCertType),
                             commandValueOrEmpty(config->sslReferenceName),
                             commandValueOrEmpty(config->tokenServerUrl)) != 0)
    {
        return -1;
    }

#ifdef FEATURE_DNS_QUERY
    if (appendParodusCommand(command, commandLen, &offset,
                             " --acquire-jwt=%d --dns-txt-url=%s --jwt-public-key-file=%s "
                             "--jwt-algo=RS256 --record-jwt-payload=%s",
                             config->acquireJwt, commandValueOrEmpty(config->dnsTextUrl),
                             JWT_KEY, RECORD_JWT_PAYLOAD_FILE) != 0)
    {
        return -1;
    }
#endif

    if (appendParodusCommand(command, commandLen, &offset,
                             " --crud-config-file=%s --boot-time-retry-wait=%d",
                             CRUD_CONFIG_FILE, config->bootTimeRetryWait) != 0)
    {
        return -1;
    }

#ifdef ENABLE_WEBCFGBIN
    if (appendParodusCommand(command, commandLen, &offset, " --max-queue-size=%d",
                             MAX_QUEUE_SIZE) != 0)
    {
        return -1;
    }
#endif

    return appendParodusCommand(command, commandLen, &offset, " &");
}

void get_url(char *parodusUrl, char *seshatUrl, char *buildType)
{
    FILE *file = fopen(DEVICE_PROPS_FILE, "r");
    errno_t rc;

    if (file != NULL)
    {
        char entry[255] = {'\0'};

        while (fscanf(file, "%254s", entry) != EOF)
        {
            char *value = NULL;

            if ((value = strstr(entry, "PARODUS_URL=")) != NULL)
            {
                value += strlen("PARODUS_URL=");
                rc = strcpy_s(parodusUrl, MAX_SERVER_URL_SIZE, value);
            }
            else if ((value = strstr(entry, "SESHAT_URL=")) != NULL)
            {
                value += strlen("SESHAT_URL=");
                rc = strcpy_s(seshatUrl, MAX_SERVER_URL_SIZE, value);
            }
            else if ((value = strstr(entry, "BUILD_TYPE=")) != NULL)
            {
                value += strlen("BUILD_TYPE=");
                rc = strcpy_s(buildType, MAX_BUILD_LEN, value);
            }
            else
            {
                continue;
            }

            if (rc != EOK)
            {
                ERR_CHK(rc);
                fclose(file);
                return;
            }
        }
        fclose(file);
    }
    else
    {
        LogError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
    }

    if (parodusUrl[0] == '\0')
    {
        LogError("parodus_url is not present in device.properties:%s\n", parodusUrl);
    }
    if (seshatUrl[0] == '\0')
    {
        LogError("seshat_url is not present in device.properties:%s\n", seshatUrl);
    }
    if (buildType[0] == '\0')
    {
        LogError("build_type is not present in device.properties:%s\n", buildType);
    }

    LogInfo("parodus_url formed is %s\n", parodusUrl);
    LogInfo("seshat_url formed is %s\n", seshatUrl);
    LogInfo("build_type is %s\n", buildType);
}

int getDeviceMac(char *deviceMac, size_t macLen)
{
    errno_t rc = -1;

    if (deviceMac == NULL || macLen == 0)
    {
        LogError("Invalid deviceMac buffer\n");
        return -1;
    }

    memset(deviceMac, 0, macLen);

#if defined(_WNXL11BWL_PRODUCT_REQ_)
    FILE *fp = popen("sh /usr/sbin/deviceinfo.sh -cmac", "r");
    if (fp != NULL)
    {
        char buffer[32] = {0};
        char *newline = NULL;

        if (fgets(buffer, sizeof(buffer), fp) != NULL && strstr(buffer, ":") != NULL)
        {
            newline = strchr(buffer, '\n');
            if (newline != NULL)
            {
                *newline = '\0';
            }
            rc = strcpy_s(deviceMac, macLen, buffer);
            if (rc != EOK)
            {
                ERR_CHK(rc);
                LogError("Failed to copy device MAC address\n");
            }
            LogInfo("XLE deviceMac is %s\n", deviceMac);
        }
        else
        {
            LogError("eth0 MAC address is empty\n");
        }
        pclose(fp);
    }
#elif defined(_COSA_BCM_MIPS_)
    dpoe_mac_address_t dpoeMac;

    if (dpoe_getOnuId(&dpoeMac) == 0)
    {
        rc = sprintf_s(deviceMac, macLen, "%02x:%02x:%02x:%02x:%02x:%02x",
                       dpoeMac.macAddress[0], dpoeMac.macAddress[1],
                       dpoeMac.macAddress[2], dpoeMac.macAddress[3],
                       dpoeMac.macAddress[4], dpoeMac.macAddress[5]);
        if (rc < EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to copy device MAC address\n");
            return -1;
        }
        LogInfo("deviceMac is %s\n", deviceMac);
    }
    else
    {
        LogError("Unable to get MAC address\n");
        return -1;
    }
#else
    char ethEnabledValue[64] = {'\0'};
    char deviceMacValue[32] = {'\0'};
    const char *defaultCmMac = "00:1A:2B:11:22:33";
    token_t token;
    int fd = s_sysevent_connect(&token);
    int ethEnabled = 0;

    if (fd < 0)
    {
        LogError("s_sysevent_connect() returned an error\n");
        return -1;
    }

    if (syscfg_get(NULL, "eth_wan_enabled", ethEnabledValue, sizeof(ethEnabledValue)) == 0 &&
        ethEnabledValue[0] != '\0')
    {
        int ind = -1;
        rc = strcmp_s("true", strlen("true"), ethEnabledValue, &ind);
        ERR_CHK(rc);
        ethEnabled = (rc == EOK && ind == 0);
    }

    if (ethEnabled && sysevent_get(fd, token, "eth_wan_mac", deviceMacValue,
                                   sizeof(deviceMacValue)) == 0 && deviceMacValue[0] != '\0')
    {
        rc = strcpy_s(deviceMac, macLen, deviceMacValue);
        if (rc != EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to copy device MAC address\n");
            return -1;
        }
        LogInfo("deviceMac is %s\n", deviceMac);
    }
    else
    {
        int maxRetryTime = 31;
        int backoffRetryTime = 0;
        int exponent = 2;

        while (1)
        {
            if (backoffRetryTime < maxRetryTime)
            {
                backoffRetryTime = (int)pow(2, exponent) - 1;
            }

#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_) && !defined(_PLATFORM_GENERICARM_) && !defined(PON_GATEWAY)
            CMMGMT_CM_DHCP_INFO dhcpinfo;
            if (cm_hal_GetDHCPInfo(&dhcpinfo) == 0)
            {
                rc = strcpy_s(deviceMac, macLen, dhcpinfo.MACAddress);
                if (rc != EOK)
                {
                    ERR_CHK(rc);
                    LogError("Failed to copy DHCP MAC address\n");
                }
            }
#else
            platform_hal_GetBaseMacAddress(deviceMac);
#endif

            if (strlen(deviceMac) != 0 && strcmp(deviceMac, defaultCmMac) != 0)
            {
                LogInfo("deviceMac is %s\n", deviceMac);
                break;
            }

            LogError("Unable to get MAC address. Retrying...\n");
            sleep(backoffRetryTime);
            exponent++;
            if (backoffRetryTime >= maxRetryTime)
            {
                LogError("Unable to get MAC address after retries\n");
                return -1;
            }
        }
    }
#endif

    return 0;
}

int getSslReferenceName(int decodeStatus, char *referenceName, size_t referenceLen)
{
    const char *referencePath = NULL;
    errno_t rc;

    if (referenceName == NULL || referenceLen == 0)
    {
        LogError("Invalid SSL reference name buffer\n");
        return -1;
    }

    memset(referenceName, 0, referenceLen);
    if (decodeStatus == 1)
    {
        referencePath = "/tmp/.cfgDynamicSExpki";
    }
    else if (decodeStatus == 2)
    {
        referencePath = "/tmp/.cfgDynamicxpki";
    }
    else if (decodeStatus == 3)
    {
        referencePath = "/tmp/.cfgStaticxpki";
    }
    else
    {
        LogError("Failed to get ssl_reference_name\n");
        return -1;
    }

    rc = strcpy_s(referenceName, referenceLen, referencePath);
    if (rc != EOK)
    {
        ERR_CHK(rc);
        LogError("Failed to copy ssl_reference_name\n");
        return -1;
    }

    LogInfo("ssl_reference_name is %s\n", referenceName);
    return 0;
}

int getSslEngine(const char *clientCertPath, char *sslEngine, size_t engineLen)
{
    errno_t rc;

    if (clientCertPath == NULL || sslEngine == NULL || engineLen == 0)
    {
        LogError("Invalid SSL engine arguments\n");
        return -1;
    }

    if (strcmp(clientCertPath, "/nvram/certs/devicecert_2.pk12") == 0)
    {
        rc = strcpy_s(sslEngine, engineLen, "e4sss");
        if (rc != EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to set ssl_engine\n");
            return -1;
        }
        LogInfo("ssl_engine is %s\n", sslEngine);
    }

    return 0;
}

int getSslCertType(char *certType, size_t certTypeLen)
{
    errno_t rc;

    if (certType == NULL || certTypeLen == 0)
    {
        LogError("Invalid SSL certificate type buffer\n");
        return -1;
    }

    rc = strcpy_s(certType, certTypeLen, "P12");
    if (rc != EOK)
    {
        ERR_CHK(rc);
        LogError("Failed to get ssl_cert_type\n");
        return -1;
    }

    LogInfo("ssl_cert_type is %s\n", certType);
    return 0;
}

int getWebpaInterface(char *interfaceName, size_t interfaceLen)
{
    errno_t rc;

    if (interfaceName == NULL || interfaceLen == 0)
    {
        LogError("Invalid WebPA interface buffer\n");
        return -1;
    }

    rc = strcpy_s(interfaceName, interfaceLen, "erouter0");
    if (rc != EOK)
    {
        ERR_CHK(rc);
        LogError("Failed to set default WebPA interface\n");
        return -1;
    }

#if defined(WAN_FAILOVER_SUPPORTED) || defined(FEATURE_RDKB_CONFIGURABLE_WAN_INTERFACE)
    token_t token;
    int fd = s_sysevent_connect(&token);
    char interfaceValue[64] = {'\0'};

    if (fd < 0)
    {
        LogError("s_sysevent_connect() returned an error\n");
        return -1;
    }

    if (sysevent_get(fd, token, "current_wan_ifname", interfaceValue,
                     sizeof(interfaceValue)) == 0)
    {
        rc = strcpy_s(interfaceName, interfaceLen, interfaceValue);
        if (rc != EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to copy WAN interface\n");
            return -1;
        }
        LogInfo("webpaInterface is %s\n", interfaceName);
    }
    else
    {
        LogError("Failed to get interface value\n");
    }
#endif

    return 0;
}

static int getValueFromCfgJson(const char *key, char **value)
{
    FILE *file;
    cJSON *json = NULL;
    cJSON *item;
    char *data = NULL;
    long fileLength;
    int status = -1;

    if (key == NULL || value == NULL)
    {
        return -1;
    }
    *value = NULL;

    file = fopen(WEBPA_CFG_FILE, "r");
    if (file == NULL)
    {
        LogError("Error opening webpa config file\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    fileLength = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (fileLength <= 0)
    {
        fclose(file);
        return -1;
    }

    data = malloc((size_t)fileLength + 1);
    if (data != NULL && fread(data, 1, (size_t)fileLength, file) == (size_t)fileLength)
    {
        data[fileLength] = '\0';
        json = cJSON_Parse(data);
    }
    fclose(file);

    if (json != NULL)
    {
        item = cJSON_GetObjectItem(json, key);
        if (item != NULL && cJSON_IsString(item) && item->valuestring != NULL)
        {
            *value = strdup(item->valuestring);
            status = *value == NULL ? -1 : 0;
        }
        cJSON_Delete(json);
    }

    free(data);
    return status;
}

int getAcquireJwt(void)
{
    char *acquireJwt = NULL;
    int jwtFlag = ACQUIRE_JWT;

    if (getValueFromCfgJson("acquire-jwt", &acquireJwt) == 0 && acquireJwt != NULL)
    {
        jwtFlag = atoi(acquireJwt);
        free(acquireJwt);
    }
    else
    {
        LogInfo("Setting default value to acquire-jwt\n");
    }

    LogInfo("acquire-jwt is %d\n", jwtFlag);
    return jwtFlag;
}

int getWebpaPingTime(void)
{
    return 180;
}

static void getSECertSupport(char *seCertSupport, size_t supportLen)
{
    FILE *file = fopen(DEVICE_PROPS_FILE, "r");
    errno_t rc;

    if (file != NULL)
    {
        char entry[255] = {'\0'};

        while (fscanf(file, "%254s", entry) != EOF)
        {
            char *value = strstr(entry, "UseSEBasedCert=");

            if (value != NULL)
            {
                value += strlen("UseSEBasedCert=");
                rc = strcpy_s(seCertSupport, supportLen, value);
                if (rc != EOK)
                {
                    ERR_CHK(rc);
                }
                break;
            }
        }
        fclose(file);
    }
    else
    {
        LogError("Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE);
    }

    if (seCertSupport[0] == '\0')
    {
        LogError("UseSEBasedCert is not present in device.properties\n");
    }
    else
    {
        LogInfo("UseSEBasedCert value is %s\n", seCertSupport);
    }
}

int getDeviceConfigFile(void)
{
    struct stat fileAttributes;
    char useSECertValue[MAX_BUF_SIZE] = {'\0'};

    getSECertSupport(useSECertValue, sizeof(useSECertValue));

    if (strncmp(useSECertValue, "true", 4) == 0 &&
        stat(SE_DEVICE_CERT, &fileAttributes) == 0)
    {
        LogInfo("Using Dynamic xPKI SE Certificate\n");
        return 1;
    }

    if (stat(DEVICE_CERT, &fileAttributes) == 0)
    {
        if (strncmp(useSECertValue, "true", 4) == 0)
        {
            LogInfo("xPKI SE Certificate not present, Using xPKI Dynamic Certificate\n");
        }
        LogInfo("Dynamic xPKI Certificate procured\n");
        return 2;
    }

    if (stat(STATIC_CERT, &fileAttributes) == 0)
    {
        LogInfo("xPKI Dynamic Certificate not present, Using xPKI Static Certificate\n");
        return 3;
    }

    LogError("no device specific xPKI Certificate created\n");
    return -1;
}

int getClientCertPath(int decodeStatus, char *clientCertPath, size_t pathLen)
{
    const char *certificatePath = NULL;
    errno_t rc;

    if (clientCertPath == NULL || pathLen == 0)
    {
        LogError("Invalid client certificate path buffer\n");
        return -1;
    }

    memset(clientCertPath, 0, pathLen);
    if (decodeStatus == 1)
    {
        certificatePath = "/nvram/certs/devicecert_2.pk12";
    }
    else if (decodeStatus == 2)
    {
        certificatePath = "/nvram/certs/devicecert_1.pk12";
    }
    else if (decodeStatus == 3)
    {
        certificatePath = "/etc/ssl/certs/staticXpkiCrt.pk12";
    }
    else
    {
        LogError("Failed to get client_cert_path\n");
        return -1;
    }

    rc = strcpy_s(clientCertPath, pathLen, certificatePath);
    if (rc != EOK)
    {
        ERR_CHK(rc);
        LogError("Failed to copy client_cert_path\n");
        return -1;
    }

    LogInfo("client_cert_path is %s\n", clientCertPath);
    return 0;
}

int getPartnerId(char *partnerId, size_t partnerIdLen)
{
    char tempPartnerId[MAX_PARTNERID_LEN] = {'\0'};
    FILE *file = NULL;
    char *newline;
    errno_t rc;
    int ind = -1;

    if (partnerId == NULL || partnerIdLen == 0)
    {
        LogError("Invalid partner ID buffer\n");
        return -1;
    }

    memset(partnerId, 0, partnerIdLen);

    if (syscfg_get(NULL, "PartnerID", partnerId, partnerIdLen) != 0 || partnerId[0] == '\0')
    {
        file = popen("/lib/rdk/getpartnerid.sh GetPartnerID", "r");
        if (file == NULL)
        {
            LogError("Error in opening file to get partner ID\n");
            return -1;
        }

        if (fgets(partnerId, (int)partnerIdLen, file) == NULL)
        {
            pclose(file);
            LogError("fgets() error\n");
            return -1;
        }
        pclose(file);

        newline = strchr(partnerId, '\n');
        if (newline != NULL)
        {
            *newline = '\0';
        }
    }

    if (partnerId[0] == '\0')
    {
        LogInfo("PartnerID is empty\n");
        return 0;
    }

    rc = strcmp_s("unknown", strlen("unknown"), partnerId, &ind);
    ERR_CHK(rc);
    if (rc != EOK || ind == 0)
    {
        partnerId[0] = '\0';
        return rc == EOK ? 0 : -1;
    }

    rc = strcpy_s(tempPartnerId, sizeof(tempPartnerId), partnerId);
    if (rc != EOK)
    {
        ERR_CHK(rc);
        return -1;
    }

    rc = sprintf_s(partnerId, partnerIdLen, "*,%s", tempPartnerId);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        LogError("Failed to frame partner ID\n");
        return -1;
    }

    LogInfo("PartnerID framed is %s\n", partnerId);
    return 0;
}

char *getWebpaUrl(const char *buildType)
{
    char *serverUrl = NULL;
    char *serverPort = NULL;
    char *webpaUrl = NULL;
    errno_t rc;

    if (buildType == NULL)
    {
        return NULL;
    }

#if defined(_PLATFORM_BANANAPI_R4_) || defined(_PLATFORM_GENERICARM_)
    file = fopen(DEVICE_PROPS_FILE, "r");
    if (file != NULL)
    {
        char line[255] = {'\0'};
        while (fscanf(file, "%254s", line) != EOF)
        {
            char *value = strstr(line, "SERVERURL=");
            if (value != NULL)
            {
                value += strlen("SERVERURL=");
                webpaUrl = strdup(value);
                break;
            }
        }
        fclose(file);
    }
#else
    if (strcmp(buildType, "dev") == 0)
    {
        if (getValueFromCfgJson(WEBPA_CFG_SERVER_URL, &serverUrl) == 0)
        {
            webpaUrl = serverUrl;
            if (strchr(webpaUrl, ':') == NULL && strstr(webpaUrl, "comcast") != NULL &&
                getValueFromCfgJson(WEBPA_CFG_SERVER_PORT, &serverPort) == 0)
            {
                char *framedUrl = malloc(MAX_SERVER_URL_SIZE);
                if (framedUrl != NULL)
                {
                    rc = sprintf_s(framedUrl, MAX_SERVER_URL_SIZE, "https://%s:%s",
                                   webpaUrl, serverPort);
                    if (rc >= EOK)
                    {
                        free(webpaUrl);
                        webpaUrl = framedUrl;
                    }
                    else
                    {
                        ERR_CHK(rc);
                        free(framedUrl);
                    }
                }
            }
        }
    }
#endif

    free(serverPort);
    LogInfo("webpaUrl returned is %s\n", webpaUrl != NULL ? webpaUrl : "(null)");
    return webpaUrl;
}

void getBootTime(unsigned int *bootTime, int *waitTime)
{
    struct sysinfo systemInfo;
    struct timeval currentTime;
    unsigned int uptime;

    if (waitTime == NULL)
    {
        LogError("Invalid boot time arguments\n");
        return;
    }

    while (!bootTime)
    {
        if (sysinfo(&systemInfo))
        {
            LogError("Failure in sysinfo fetch.\n");
        }
        else
        {
            uptime = systemInfo.uptime;
            gettimeofday(&currentTime, NULL);
            bootTime = (unsigned int)(currentTime.tv_sec - uptime);
        }

        if (bootTime > 0 && bootTime < UINT_MAX)
        {
            LogInfo("bootTime is %u\n", bootTime);
        }
        else if (*waitTime >= 60)
        {
            LogError("boot_time is %u. Unable to get valid bootTime even after wait of 60s. Hence setting bootTime value to 0.\n", bootTime);
            bootTime = 0;
            break;
        }
        else
        {
            LogError("boot_time %u is not valid, retry after 10s\n", bootTime);
            bootTime = 0;
            sleep(10);
            *waitTime += 10;
        }
    }
}

void getModelName(char *modelName, size_t len)
{
    if (NULL == modelName || 0 == len)
    {
        LogError("Invalid modelName buffer\n");
        return;
    }

    memset(modelName, 0, len);

    if (platform_hal_GetModelName(modelName) == 0)
    {
        LogInfo("modelName returned from hal:%s\n", modelName);
    }
    else
    {
        LogError("Unable to get ModelName\n");
    }
}

void getSerialNumber(char *serialNumber, size_t len)
{
    if (NULL == serialNumber || 0 == len)
    {
        LogError("Invalid serialNumber buffer\n");
        return;
    }

    memset(serialNumber, 0, len);

    if (platform_hal_GetSerialNumber(serialNumber) == 0)
    {
        LogInfo("serialNumber returned from hal:%s\n", serialNumber);
    }
    else
    {
        LogError("Unable to get SerialNumber\n");
    }
}

void getFirmwareName(char *fwName, size_t fwNameLen)
{
    if (NULL == fwName || 0 == fwNameLen)
    {
        LogError("Invalid fwName buffer\n");
        return;
    }

    memset(fwName, 0, fwNameLen);

    if (platform_hal_GetFirmwareName(fwName, fwNameLen) == 0)
    {
        LogInfo("firmwareVersion returned from hal:%s\n", fwName);
    }
    else
    {
        LogError("Unable to get FirmwareName\n");
    }
}

void getManufacturer(char *manufacturer, size_t len)
{
    errno_t rc;

    if (NULL == manufacturer || 0 == len)
    {
        LogError("Invalid manufacturer buffer\n");
        return;
    }

    rc = strcpy_s(manufacturer, len, CONFIG_VENDOR_NAME);
    if (rc != EOK)
    {
        ERR_CHK(rc);
        LogError("Failed to get manufacturer name\n");
        return;
    }
    LogInfo("Manufacturer Name is %s\n", manufacturer);
}

void getRebootReason(char *reason, size_t reasonLen)
{
    char rebootCounter[8] = {'\0'};
    char lastRebootReason[128] = {'\0'};
    errno_t rc;
    unsigned int i = 0, j = 0;

    if (NULL == reason || 0 == reasonLen)
    {
        LogError("Invalid reason buffer\n");
        return;
    }

    memset(reason, 0, reasonLen);

    if (syscfg_init() != 0)
    {
        LogError("syscfg init failure\n");
        rc = strcpy_s(reason, reasonLen, "unknown");
        if (rc != EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to copy reboot reason as unknown\n");
        }
        return;
    }

    syscfg_get(NULL, "X_RDKCENTRAL-COM_LastRebootCounter", rebootCounter, sizeof(rebootCounter));

    /* /var/tmp/lastrebootreason file is created in PAM during bootup. When parodus starts early before PAM, /var/tmp/lastrebootreason file does not exists and if reboot counter is 0, reason is updated as unknown */
    if (access("/var/tmp/lastrebootreason", F_OK) != 0 && (strlen(rebootCounter) > 0 && atoi(rebootCounter) == 0))
    {
        LogInfo("/var/tmp/lastrebootreason file doesn't exist and rebootCounter is %s\n", rebootCounter);
        rc = strcpy_s(reason, reasonLen, "unknown");
        if (rc != EOK)
        {
            ERR_CHK(rc);
            LogError("Failed to copy final_lastRebootReason as unknown\n");
        }
        return;
    }

    syscfg_get(NULL, "X_RDKCENTRAL-COM_LastRebootReason", lastRebootReason, sizeof(lastRebootReason));
    LogInfo("lastRebootReason is %s\n", lastRebootReason);

    /* Strip all spaces and parentheses from reboot reason to make it one word */
    /* This also prevents command line parsing issues due to value like '-s' */
    for (i = 0; i < sizeof(lastRebootReason) && j < reasonLen; i++)
    {
        if (lastRebootReason[i] != ' ' && lastRebootReason[i] != '(' && lastRebootReason[i] != ')')
        {
            reason[j] = lastRebootReason[i];
            j++;
        }
    }

    LogInfo("Modified lastRebootReason is %s\n", reason);
}

static void sync_free_values(char *values[], int count)
{
    int i;

    for (i = 0; i < count; i++)
    {
        free(values[i]);
        values[i] = NULL;
    }
}

static int sync_get_psm_values(char *names[], char *values[], int count)
{
    FILE *output;
    char command[MAX_BUF_SIZE] = {'\0'};
    char request[MAX_BUF_SIZE] = {'\0'};
    char buffer[MAX_BUF_SIZE] = {'\0'};
    char value[MAX_VALUE_SIZE] = {'\0'};
    int offset = 0;
    int index = 0;
    int i;
    int rc;

    for (i = 0; i < count; i++)
    {
        rc = sprintf_s(request + offset, sizeof(request) - offset,
                       " %dX %s%s", i, PSM_PATH_PREFIX, names[i]);
        if (rc < EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
        offset += rc;
    }

    rc = sprintf_s(command, sizeof(command), "psmcli get -e%s", request);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
    }

    output = popen(command, "r");
    if (output == NULL)
    {
        LogError("Failed to execute PSM get command\n");
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        if (fgets(buffer, sizeof(buffer), output) == NULL)
        {
            LogError("Failed to read PSM value\n");
            pclose(output);
            return -1;
        }

        if (sscanf(buffer, "%dX=\"%63[^\"]", &index, value) == 2 && index == i)
        {
            values[i] = strdup(value);
        }
    }

    pclose(output);
    return 0;
}

static int getPartnerUrl(const char *partnerId, const char *paramName, char **value)
{
    FILE *file;
    cJSON *json = NULL;
    cJSON *partnerObject;
    cJSON *item;
    char *data = NULL;
    char partnerKey[MAX_PARTNERID_LEN] = {'\0'};
    long length;
    errno_t rc;

    if (partnerId == NULL || partnerId[0] == '\0' || paramName == NULL || value == NULL)
    {
        return -1;
    }
    *value = NULL;
    rc = strcpy_s(partnerKey, sizeof(partnerKey), partnerId[0] == '*' ? partnerId + 2 : partnerId);
    if (rc != EOK)
    {
        ERR_CHK(rc);
        return -1;
    }

    file = fopen("/etc/partners_defaults.json", "r");
    if (file == NULL)
    {
        return -1;
    }
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (length <= 0)
    {
        fclose(file);
        return -1;
    }
    data = malloc((size_t)length + 1);
    if (data != NULL && fread(data, 1, (size_t)length, file) == (size_t)length)
    {
        data[length] = '\0';
        json = cJSON_Parse(data);
    }
    fclose(file);

    if (json != NULL)
    {
        partnerObject = cJSON_GetObjectItem(json, partnerKey);
        item = partnerObject == NULL ? NULL : cJSON_GetObjectItem(partnerObject, paramName);
        if (item != NULL && cJSON_IsString(item) && item->valuestring != NULL)
        {
            *value = strdup(item->valuestring);
        }
        cJSON_Delete(json);
    }
    free(data);
    return *value == NULL ? -1 : 0;
}

static void updatePartnerUrls(const char *partnerId, char **serverUrl,
                              char **tokenServerUrl, char **dnsTextUrl)
{
    const char *names[] = {
        "Device.X_RDKCENTRAL-COM_Webpa.Server.URL",
        "Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL",
        "Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL"
    };
    char **values[] = {serverUrl, tokenServerUrl, dnsTextUrl};
    int i;
    char *value;

    for (i = 0; i < 3; i++)
    {
        if (*values[i] == NULL || (*values[i])[0] == '\0')
        {
            if (getPartnerUrl(partnerId, names[i], &value) == 0)
            {
                free(*values[i]);
                *values[i] = value;
            }
        }
    }
}

int getWebpaConfig(const char *buildType, const char *partnerId, char **webpaUrl,
                   char **tokenServerUrl, char **dnsTextUrl)
{
    char *paramNames[] = {
        "Device.X_RDKCENTRAL-COM_Webpa.Server.URL",
        "Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL",
        "Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL"
    };
    char *values[3] = {NULL};
    char *serverUrl = NULL;
    int status = -1;

    if (webpaUrl == NULL || tokenServerUrl == NULL || dnsTextUrl == NULL)
    {
        LogError("Invalid WebPA URL output arguments\n");
        return -1;
    }

    *webpaUrl = getWebpaUrl(buildType);
    *tokenServerUrl = NULL;
    *dnsTextUrl = NULL;

    if (sync_get_psm_values(paramNames, values, 3) != 0)
    {
        goto cleanup;
    }

    if (values[0] != NULL)
    {
        serverUrl = strdup(values[0]);
    }
    if (values[1] != NULL)
    {
        *tokenServerUrl = strdup(values[1]);
    }
    if (values[2] != NULL)
    {
        *dnsTextUrl = strdup(values[2]);
    }

    if (partnerId != NULL && partnerId[0] != '\0')
    {
        updatePartnerUrls(partnerId, &serverUrl, tokenServerUrl, dnsTextUrl);
    }

    if (*webpaUrl == NULL || (*webpaUrl)[0] == '\0')
    {
        if (serverUrl != NULL && serverUrl[0] != '\0')
        {
            free(*webpaUrl);
            *webpaUrl = strdup(serverUrl);
        }
    }

    if ((values[0] != NULL && serverUrl == NULL) ||
        (values[1] != NULL && *tokenServerUrl == NULL) ||
        (values[2] != NULL && *dnsTextUrl == NULL))
    {
        LogError("Failed to allocate WebPA URL values\n");
        goto cleanup;
    }

    if (*webpaUrl == NULL || (*webpaUrl)[0] == '\0')
    {
        LogError("Unable to determine WebPA URL\n");
        goto cleanup;
    }

    LogInfo("WEBPA URL values fetched: webpa=%s server=%s token=%s dns=%s\n",
            *webpaUrl != NULL ? *webpaUrl : "(null)",
            serverUrl != NULL ? serverUrl : "(null)",
            *tokenServerUrl != NULL ? *tokenServerUrl : "(null)",
            *dnsTextUrl != NULL ? *dnsTextUrl : "(null)");
    status = 0;

cleanup:
    free(values[0]);
    free(values[1]);
    free(values[2]);
    free(serverUrl);
    if (status != 0)
    {
        free(*webpaUrl);
        free(*tokenServerUrl);
        free(*dnsTextUrl);
        *webpaUrl = NULL;
        *tokenServerUrl = NULL;
        *dnsTextUrl = NULL;
    }
    return status;
}

static int sync_set_psm_values(char *names[], char *values[], int count)
{
    FILE *output;
    char command[MAX_BUF_SIZE] = {'\0'};
    char request[MAX_BUF_SIZE] = {'\0'};
    char buffer[32] = {'\0'};
    int offset = 0;
    int result = 0;
    int i;
    int rc;

    for (i = 0; i < count; i++)
    {
        rc = sprintf_s(request + offset, sizeof(request) - offset,
                       " %s%s %s", PSM_PATH_PREFIX, names[i], values[i]);
        if (rc < EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
        offset += rc;
    }

    rc = sprintf_s(command, sizeof(command), "psmcli set%s", request);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return -1;
    }

    output = popen(command, "r");
    if (output == NULL)
    {
        LogError("Failed to execute PSM set command\n");
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        if (fgets(buffer, sizeof(buffer), output) == NULL || sscanf(buffer, "%d", &result) != 1 || result != 100)
        {
            LogError("Failed to set PSM value\n");
            pclose(output);
            return -1;
        }
    }

    pclose(output);
    return 0;
}

static int syncXpcParamsOnUpgrade(char *firmwareVersion)
{
    char lastRebootReason[128] = {'\0'};
    char *paramList[] = {"X_COMCAST-COM_CMC", "X_COMCAST-COM_CID", "X_COMCAST-COM_SyncProtocolVersion"};
    char *psmValues[3] = {NULL};
    char *sysCfgValues[3] = {NULL};
    char *configFirmware = NULL;
    FILE *configFile = NULL;
    cJSON *configJson = NULL;
    cJSON *firmwareItem = NULL;
    char *configData = NULL;
    char *updatedConfig = NULL;
    long configLength;
    int parodusEnable = 0;
    int status = -1;
    int i;
    int ind = -1;
    errno_t rc;

    syscfg_get(NULL, "X_RDKCENTRAL-COM_LastRebootReason", lastRebootReason, sizeof(lastRebootReason));
    configFile = fopen(WEBPA_CFG_FILE, "r");
    if (configFile != NULL)
    {
        fseek(configFile, 0, SEEK_END);
        configLength = ftell(configFile);
        fseek(configFile, 0, SEEK_SET);
        if (configLength > 0)
        {
            configData = malloc((size_t)configLength + 1);
            if (configData != NULL && fread(configData, 1, (size_t)configLength, configFile) == (size_t)configLength)
            {
                configData[configLength] = '\0';
                configJson = cJSON_Parse(configData);
            }
        }
        fclose(configFile);
    }

    if (configJson != NULL)
    {
        firmwareItem = cJSON_GetObjectItem(configJson, WEBPA_CFG_FIRMWARE_VER);
        if (firmwareItem != NULL && cJSON_IsString(firmwareItem) && firmwareItem->valuestring != NULL)
        {
            configFirmware = firmwareItem->valuestring;
        }
    }

    rc = strcmp_s("Software_upgrade", strlen("Software_upgrade"), lastRebootReason, &ind);
    ERR_CHK(rc);
    if (rc == EOK && ind == 0)
    {
        parodusEnable = 1;
    }
    else if (configFirmware != NULL)
    {
        rc = strcmp_s(firmwareVersion, strlen(firmwareVersion), configFirmware, &ind);
        ERR_CHK(rc);
        if (rc == EOK && ind != 0)
        {
            parodusEnable = 1;
        }
    }

    if (sync_get_psm_values(paramList, psmValues, 3) != 0)
    {
        goto cleanup;
    }

    if (parodusEnable && psmValues[0] != NULL && psmValues[1] != NULL && psmValues[2] != NULL &&
        atoi(psmValues[0]) == 0 && atoi(psmValues[1]) == 0 && atoi(psmValues[2]) == 0)
    {
        for (i = 0; i < 3; i++)
        {
            sysCfgValues[i] = malloc(MAX_VALUE_SIZE);
            if (sysCfgValues[i] == NULL || syscfg_get(NULL, paramList[i], sysCfgValues[i], MAX_VALUE_SIZE) != 0)
            {
                LogError("Failed to get Syscfg value for %s\n", paramList[i]);
                goto cleanup;
            }
        }

        status = sync_set_psm_values(paramList, sysCfgValues, 3);
        if (status == 0)
        {
            LogInfo("Successfully set values to PSM DB\n");
        }
    }

#ifdef UPDATE_CONFIG_FILE
    if (configJson != NULL)
    {
        cJSON_ReplaceItemInObject(configJson, WEBPA_CFG_FIRMWARE_VER, cJSON_CreateString(firmwareVersion));
        updatedConfig = cJSON_Print(configJson);
        if (updatedConfig != NULL)
        {
            configFile = fopen(WEBPA_CFG_FILE, "w");
            if (configFile != NULL)
            {
                fwrite(updatedConfig, strlen(updatedConfig), 1, configFile);
                fclose(configFile);
            }
        }
    }
#endif

cleanup:
    free(updatedConfig);
    free(configData);
    cJSON_Delete(configJson);
    sync_free_values(psmValues, 3);
    sync_free_values(sysCfgValues, 3);
    return status;
}

static void waitForPSMHealth(const char *compName)
{
    int count = 0;
    char command[128] = {0};
    char parameterName[128] = {0};
    char componentStatus[32] = {0};
    errno_t rc;
    int ind = -1;

    rc = sprintf_s(parameterName, sizeof(parameterName), "%s.Health", compName);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return;
    }

    while (1)
    {
        FILE *output;

        rc = sprintf_s(command, sizeof(command),
                       "dmcli eRT getv %s.Health | grep value | awk '{print $5}'",
                       compName);
        if (rc < EOK)
        {
            ERR_CHK(rc);
            return;
        }

        output = popen(command, "r");
        if (output == NULL)
        {
            LogError("Error in getting status\n");
            return;
        }

        if (fscanf(output, "%31s", componentStatus) == EOF)
        {
            LogError("Error in fscanf() return\n");
        }
        pclose(output);

        rc = strcmp_s("Green", strlen("Green"), componentStatus, &ind);
        ERR_CHK(rc);
        if (rc == EOK && ind == 0)
        {
            break;
        }

        if (count > 5)
        {
            LogError("%s component has failed . Proceeding with Parodus start up\n",
                     parameterName);
            return;
        }

        LogError("%s component is not up, waiting\n", parameterName);
        sleep(10);
        count++;
    }

    LogInfo("%s component health is green, continue\n", parameterName);
}

int syncPsmDbOnUpgrade(char *firmwareVersion)
{
    char *paramList[] = {
        "X_COMCAST-COM_CMC",
        "X_COMCAST-COM_CID",
        "X_COMCAST-COM_SyncProtocolVersion"
    };
    char *psmValues[3] = {NULL};
    int syncStatus;

    waitForPSMHealth(PSM_COMPONENT_NAME);
    syncStatus = syncXpcParamsOnUpgrade(firmwareVersion);

    if (syncStatus == 0)
    {
        LogInfo("DB synced successfully on firmware upgrade\n");
    }
    else if (syncStatus == -2)
    {
        LogInfo("PARODUS: Failed to sync DB during Firmware Upgrade\n");
    }
    else
    {
        LogInfo("DB sync is not required or failed to sync!!\n");
    }

    if (sync_get_psm_values(paramList, psmValues, 3) == 0)
    {
        LogInfo("DB details are %s = %s %s = %s %s = %s\n",
                paramList[0], psmValues[0] != NULL ? psmValues[0] : "(null)",
                paramList[1], psmValues[1] != NULL ? psmValues[1] : "(null)",
                paramList[2], psmValues[2] != NULL ? psmValues[2] : "(null)");
    }
    else
    {
        LogError("Failed to fetch PSM DB details\n");
    }
    sync_free_values(psmValues, 3);

    return syncStatus;
}
