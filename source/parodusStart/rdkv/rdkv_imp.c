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
 * @file rdkv_imp.c
 *
 * @description RDKV specific implementation of the parodusStart helpers.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "cJSON.h"
#include "rfcapi.h"
#include "rdkv_imp.h"

#define WEBPA_CFG_FILE            "/etc/webpa_cfg.json"
#define WEBPA_CFG_OVERIDE_FILE    "/opt/webpa_cfg.json"
#define CRUD_CONFIG_FILE          "/opt/secure/parodus_cfg.json"
#define REBOOT_REASON_SECURE_FILE "/opt/secure/reboot/previousreboot.info"
#define HWMAC_FILE                "/tmp/.macAddress"
#define VERSION_FILE              "/version.txt"
#define PARTNERID_FILE            "/opt/www/authService/partnerId3.dat"
#define UNKNOWN_PARTNERID         "unknown"
#define PARTNERID_APPEND          "*,"

#define DNS_TEXT_URL_PARAM        "Device.X_RDK_WebPA_DNSText.URL"
#define TOKEN_SERVER_URL_PARAM    "Device.X_RDK_WebPA_TokenServer.URL"
#define SERVER_IP_URL_PARAM       "Device.X_RDK_WebPA_Server.URL"
#define SERIAL_NUMBER_PARAM       "Device.DeviceInfo.SerialNumber"
#define BOOT_TIME_PARAM           "Device.DeviceInfo.X_RDKCENTRAL-COM_BootTime"
#define PARTNERID_PARAM           "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.PartnerId"

#ifndef CONFIG_RES_FILE  // please update with the original value based on your device
#define CONFIG_RES_FILE "/tmp/data"
#endif

#define VALUE_LEN                 1024

static char g_dnsTextUrl[VALUE_LEN] = {'\0'};
static char g_tokenServerUrl[VALUE_LEN] = {'\0'};
static char g_webpaInterface[BUFFER_LEN_64] = {'\0'};
static int g_acquireJwt = 0;
static int g_webpaPingTime = 0;

void rdkv_log(int level, const char *msg, ...)
{
    va_list arg_ptr;

    va_start(arg_ptr, msg);
    vfprintf(level == RDKV_LOG_ERROR ? stderr : stdout, msg, arg_ptr);
    va_end(arg_ptr);
}

FILE *log_init(void)
{
    return stdout;
}

void log_close(void)
{
}

/* RDKV does not publish the command; parodus is launched directly. */
int publishParodusCommand(const char *command)
{
    (void)command;
    return 0;
}

static void copyValue(char *dst, size_t dstLen, const char *src)
{
    if (dst == NULL || dstLen == 0)
    {
        return;
    }
    snprintf(dst, dstLen, "%s", src != NULL ? src : "");
}

static void removeNewlines(char *str)
{
    char *dst = str;
    for (; *str != '\0'; str++)
    {
        if (*str != '\n')
        {
            *dst++ = *str;
        }
    }
    *dst = '\0';
}

/* Strip characters which can break out of the quoted shell argument. */
static void sanitizeShellValue(char *str)
{
    char *dst = str;
    for (; *str != '\0'; str++)
    {
        if (*str != '"' && *str != '`' && *str != '$' && *str != '\\' && *str != '\n')
        {
            *dst++ = *str;
        }
    }
    *dst = '\0';
}

static const char *valueOrEmpty(const char *value)
{
    return value != NULL ? value : "";
}

/* Reads the whole file into a NUL terminated buffer, returns length or -1. */
static long readFile(const char *path, char *buf, size_t bufLen)
{
    FILE *fp;
    int fd;
    size_t bytesRead;

    fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL)
    {
        close(fd);
        return -1;
    }
    bytesRead = fread(buf, 1, bufLen - 1, fp);
    buf[bytesRead] = '\0';
    fclose(fp);
    return (long)bytesRead;
}

static int getRfcValue(const char *paramName, char *value, size_t valueLen)
{
    RFC_ParamData_t param;

    memset(&param, 0, sizeof(param));
    getRFCParameter((char *)"webcfg", (char *)paramName, &param);
    if (strlen(param.value) == 0)
    {
        return -1;
    }
    LogInfo("[%s:%d] %s RFC PARAM VALUE = [ %s ]\n", __FUNCTION__, __LINE__, paramName, param.value);
    copyValue(value, valueLen, param.value);
    return 0;
}

void get_url(char *parodusUrl, char *seshatUrl, char *buildType)
{
    /* Not used on RDKV; parodus defaults are applied. */
    (void)parodusUrl;
    (void)seshatUrl;
    (void)buildType;
}

int getDeviceMac(char *deviceMac, size_t macLen)
{
    char tempMAC[18] = {'\0'};
    size_t src, dst = 0;
    FILE *fp;

    if (deviceMac == NULL || macLen == 0)
    {
        return -1;
    }
    deviceMac[0] = '\0';
    fp = fopen(HWMAC_FILE, "r");
    if (fp == NULL)
    {
        LogError("Unable to open %s\n", HWMAC_FILE);
        return 0;
    }
    size_t bytesRead = fread(tempMAC, 1, sizeof(tempMAC) - 1, fp);
    fclose(fp);
    LogInfo("The value of bytes read: %zu\n", bytesRead);
    for (src = 0; src < bytesRead && dst < 12 && dst + 1 < macLen; src++)
    {
        if (tempMAC[src] != ':')
        {
            deviceMac[dst++] = tempMAC[src];
        }
    }
    deviceMac[dst] = '\0';
    return 0;
}

int getPartnerId(char *partnerId, size_t partnerIdLen)
{
    char id[BUFFER_LEN_128] = {'\0'};
    long len;

    if (partnerId == NULL || partnerIdLen == 0)
    {
        return -1;
    }
    partnerId[0] = '\0';

    len = readFile(PARTNERID_FILE, id, sizeof(id));
    if (len < 0)
    {
        getRfcValue(PARTNERID_PARAM, id, sizeof(id));
    }
    else if (len == 0)
    {
        LogInfo("Partner ID file is Empty %s\n", PARTNERID_FILE);
    }

    if (strcmp(id, UNKNOWN_PARTNERID) == 0)
    {
        return 0;
    }
    snprintf(partnerId, partnerIdLen, "%s%s", PARTNERID_APPEND, id);
    removeNewlines(partnerId);
    LogInfo("[%s:%d]PartnerId = [ %s ]\n", __FUNCTION__, __LINE__, partnerId);
    return 0;
}

static void loadWebpaCfgFile(char **webpaUrl)
{
    char cfg[VALUE_LEN * 4] = {'\0'};
    cJSON *json;
    cJSON *item;
    long len = readFile(WEBPA_CFG_OVERIDE_FILE, cfg, sizeof(cfg));

    if (len < 0)
    {
        len = readFile(WEBPA_CFG_FILE, cfg, sizeof(cfg));
    }
    if (len < 0)
    {
        LogError("Failed to open Webpa cfg file %s\n", WEBPA_CFG_FILE);
        return;
    }
    if (len == 0)
    {
        LogInfo("WebPA config file is Empty %s\n", WEBPA_CFG_FILE);
        return;
    }

    json = cJSON_Parse(cfg);
    if (json == NULL)
    {
        return;
    }

    item = cJSON_GetObjectItem(json, "ServerIP");
    if (item != NULL && item->valuestring != NULL && (*webpaUrl)[0] == '\0')
    {
        char *url = strdup(item->valuestring);
        if (url != NULL)
        {
            free(*webpaUrl);
            *webpaUrl = url;
        }
    }
    item = cJSON_GetObjectItem(json, "acquire-jwt");
    if (item != NULL)
    {
        g_acquireJwt = item->valueint;
        LogInfo("acquireJWT = [ %d ]\n", g_acquireJwt);
    }
    item = cJSON_GetObjectItem(json, "DeviceNetworkInterface");
    if (item != NULL && item->valuestring != NULL)
    {
        copyValue(g_webpaInterface, sizeof(g_webpaInterface), item->valuestring);
        LogInfo("NetworkIF = [ %s ]\n", g_webpaInterface);
    }
    item = cJSON_GetObjectItem(json, "MaxPingWaitTimeInSec");
    if (item != NULL)
    {
        g_webpaPingTime = item->valueint;
        LogInfo("pingWaitTime = [ %d ]\n", g_webpaPingTime);
    }
    cJSON_Delete(json);
}

int getWebpaConfig(const char *buildType, const char *partnerId, char **webpaUrl,
        char **tokenServerUrl, char **dnsTextUrl)
{
    char rfcUrl[VALUE_LEN] = {'\0'};

    (void)buildType;
    (void)partnerId;

    if (webpaUrl == NULL || tokenServerUrl == NULL || dnsTextUrl == NULL)
    {
        return -1;
    }

    getRfcValue(SERVER_IP_URL_PARAM, rfcUrl, sizeof(rfcUrl));
    *webpaUrl = strdup(rfcUrl);
    if (*webpaUrl == NULL)
    {
        return -1;
    }
    /* RFC value takes precedence; cfg file ServerIP is used only when it is empty */
    loadWebpaCfgFile(webpaUrl);

    getRfcValue(DNS_TEXT_URL_PARAM, g_dnsTextUrl, sizeof(g_dnsTextUrl));
    getRfcValue(TOKEN_SERVER_URL_PARAM, g_tokenServerUrl, sizeof(g_tokenServerUrl));
    *dnsTextUrl = g_dnsTextUrl;
    *tokenServerUrl = g_tokenServerUrl;
    return 0;
}

int getAcquireJwt(void)
{
    return g_acquireJwt;
}

int getWebpaPingTime(void)
{
    return g_webpaPingTime;
}

int getDeviceConfigFile(void)
{
    /* Placeholder for platforms needing a device config file (RDKCLISSA) */
    return 0;
}

int getClientCertPath(int decodeStatus, char *clientCertPath, size_t pathLen)
{
    struct stat status;

    (void)decodeStatus;
    if (clientCertPath == NULL || pathLen == 0)
    {
        return -1;
    }
    clientCertPath[0] = '\0';
    if (stat(CONFIG_RES_FILE, &status) == 0)
    {
        copyValue(clientCertPath, pathLen, CONFIG_RES_FILE);
    }
    return 0;
}

int getSslReferenceName(int decodeStatus, char *referenceName, size_t referenceLen)
{
    (void)decodeStatus;
    (void)referenceName;
    (void)referenceLen;
    return 0;
}

int getSslEngine(const char *clientCertPath, char *sslEngine, size_t engineLen)
{
    (void)clientCertPath;
    (void)sslEngine;
    (void)engineLen;
    return 0;
}

int getSslCertType(char *certType, size_t certTypeLen)
{
    (void)certType;
    (void)certTypeLen;
    return 0;
}

int getWebpaInterface(char *interfaceName, size_t interfaceLen)
{
    if (interfaceName == NULL || interfaceLen == 0)
    {
        return -1;
    }
    /* Interface comes from the webpa cfg file; empty when not configured */
    copyValue(interfaceName, interfaceLen, g_webpaInterface);
    return 0;
}

void getBootTime(unsigned int *bootTime, int *waitTime)
{
    char value[BUFFER_LEN_64] = {'\0'};

    if (bootTime != NULL)
    {
        *bootTime = 0;
        if (getRfcValue(BOOT_TIME_PARAM, value, sizeof(value)) == 0)
        {
            *bootTime = (unsigned int)strtoul(value, NULL, 10);
        }
    }
    if (waitTime != NULL)
    {
        *waitTime = 0;
    }
}

void getModelName(char *modelName, size_t len)
{
    copyValue(modelName, len, getenv("MODEL_NUM"));
}

void getSerialNumber(char *serialNumber, size_t len)
{
    char value[BUFFER_LEN_256] = {'\0'};

    getRfcValue(SERIAL_NUMBER_PARAM, value, sizeof(value));
    copyValue(serialNumber, len, value);
}

void getFirmwareName(char *fwName, size_t fwNameLen)
{
    char line[BUFFER_LEN_128] = {'\0'};
    char *token;
    FILE *fp;

    if (fwName == NULL || fwNameLen == 0)
    {
        return;
    }
    fwName[0] = '\0';
    fp = fopen(VERSION_FILE, "r");
    if (fp == NULL)
    {
        return;
    }
    if (fgets(line, sizeof(line), fp) != NULL)
    {
        strtok(line, ":");
        token = strtok(NULL, ":");
        if (token != NULL)
        {
            copyValue(fwName, fwNameLen, token);
            removeNewlines(fwName);
        }
        else
        {
            LogError("Error: Token is null\n");
        }
    }
    fclose(fp);
}

void getManufacturer(char *manufacturer, size_t len)
{
    copyValue(manufacturer, len, getenv("MANUFACTURE"));
}

void getRebootReason(char *reason, size_t reasonLen)
{
    char buf[VALUE_LEN] = {'\0'};
    cJSON *json;
    cJSON *item;
    long len;

    if (reason == NULL || reasonLen == 0)
    {
        return;
    }
    reason[0] = '\0';

    len = readFile(REBOOT_REASON_SECURE_FILE, buf, sizeof(buf));
    if (len < 0)
    {
        LogError("Failed to open reboot reason file %s\n", REBOOT_REASON_SECURE_FILE);
        return;
    }
    if (len == 0)
    {
        LogInfo("Reboot reason file is Empty %s\n", REBOOT_REASON_SECURE_FILE);
        return;
    }
    json = cJSON_Parse(buf);
    if (json == NULL)
    {
        return;
    }
    item = cJSON_GetObjectItem(json, "reason");
    if (item != NULL && item->valuestring != NULL)
    {
        copyValue(reason, reasonLen, item->valuestring);
        removeNewlines(reason);
    }
    cJSON_Delete(json);
}

int buildParodusCommand(char *command, size_t commandLen,
        const ParodusCommandConfig *config)
{
    char rebootReason[BUFFER_LEN_128] = {'\0'};
    int written;

    if (command == NULL || commandLen == 0 || config == NULL)
    {
        LogError("buildParodusCommand: invalid input\n");
        return -1;
    }
    copyValue(rebootReason, sizeof(rebootReason), config->lastRebootReason);
    sanitizeShellValue(rebootReason);

    written = snprintf(command, commandLen,
            "backgroundrun /usr/bin/parodus "
            "--hw-mac=%s --webpa-ping-time=%d --webpa-interface-used=%s --webpa-url=%s "
            "--partner-id=%s --webpa-backoff-max=9 --ssl-cert-path=%s --acquire-jwt=%d "
            "--dns-txt-url=%s --jwt-public-key-file=%s --jwt-algo=RS256 --record-jwt-payload=%s "
            "--crud-config-file=%s --hw-manufacturer=%s --fw-name=%s --hw-model=%s "
            "--hw-serial-number=%s --boot-time=%u --hw-last-reboot-reason=\"%s\" "
            "--client-cert-path=%s --token-server-url=%s",
            valueOrEmpty(config->deviceMac), config->webpaPingTime,
            valueOrEmpty(config->webpaInterface), valueOrEmpty(config->webpaUrl),
            valueOrEmpty(config->partnerId), SSL_CERT_BUNDLE, config->acquireJwt,
            valueOrEmpty(config->dnsTextUrl), JWT_KEY, RECORD_JWT_PAYLOAD_FILE,
            CRUD_CONFIG_FILE, valueOrEmpty(config->manufacturer),
            valueOrEmpty(config->firmwareVersion), valueOrEmpty(config->modelName),
            valueOrEmpty(config->serialNumber), config->bootTime, rebootReason,
            valueOrEmpty(config->clientCertPath), valueOrEmpty(config->tokenServerUrl));
    if (written < 0 || (size_t)written >= commandLen)
    {
        LogError("buildParodusCommand: command buffer too small\n");
        return -1;
    }
    return 0;
}

int startParodusProcess(const char *command)
{
    if (command == NULL)
    {
        LogError("Invalid parodus command\n");
        return -1;
    }
    LogInfo("Starting parodus process ..\n");
    return system(command);
}
