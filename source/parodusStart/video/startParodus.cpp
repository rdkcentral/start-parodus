
/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2017 RDK Management
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

#include <string.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "cJSON.h"
#include "rfcapi.h"
#include "hostIf_utils.h"
//#include "rdk_debug.h"
#include "secure_wrapper.h"
#include <signal.h>
#include <glib.h>
#include <algorithm>
#include <string>

#define WEBPA_CFG_FILE "/etc/webpa_cfg.json"
#define WEBPA_CFG_OVERIDE_FILE "/opt/webpa_cfg.json"
#define CRUD_CONFIG_FILE "/opt/secure/parodus_cfg.json"
#define SSL_CERT_FILE "/etc/ssl/certs/ca-certificates.crt"
#define JWT_KEY "/etc/ssl/certs/webpa-rs256.pem"
#define RECORD_JWT_PAYLOAD_FILE "/tmp/xmidt-jwt-payload.json"
#define DNS_TEXT_URL "Device.X_RDK_WebPA_DNSText.URL"
#define TOKEN_SERVER_URL "Device.X_RDK_WebPA_TokenServer.URL"
#define REBOOT_REASON_SECURE_FILE "/opt/secure/reboot/previousreboot.info"
#define SERVER_IP_URL "Device.X_RDK_WebPA_Server.URL"
#define SERIAL_NUMBER "Device.DeviceInfo.SerialNumber"
#define BOOT_TIME "Device.DeviceInfo.X_RDKCENTRAL-COM_BootTime"
#define HWMAC_FILE "/tmp/.macAddress"
#define VERSION_FILE "/version.txt"
#define PARTNERID_FILE "/opt/www/authService/partnerId3.dat"
#define PARTNERID "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.PartnerId"
#define UNKNOWN_PARTNERID "unknown"
#define PARTNERID_APPEND "*,"
#define MAX_PARTNER_ID_SIZE 128

#ifndef CONFIG_RES_FILE  // please update with the orginal value based on your device
#define CONFIG_RES_FILE "/tmp/data"
#endif

#ifdef RDKCLISSA
    void getDeviceConfigFile();
#endif

static void processExit(int sig)
{
    printf("Process Exit handling %d\n", sig);
}

std::string get_HWMAcAddress()
{
    FILE *fp = NULL;
    int srcCount = 0;
    int dstCount = 0;
    char tempMAC[17] = {0};
    char HwMac[14] = "";
    std::string hwAddr;

    fp = fopen(HWMAC_FILE, "r");
    if (fp != NULL)
    {
        size_t bytesRead = fread(tempMAC, 1, 17, fp);
        printf("The value of bytes read: %zu\n", bytesRead);
        fclose(fp);
        for (srcCount = 0; dstCount < 12 && srcCount < 17; srcCount++)
        {
            if (tempMAC[srcCount] == ':')
            {
                continue;
            }
            HwMac[dstCount] = tempMAC[srcCount];
            dstCount++;
        }
        HwMac[13] = '\0';
        fp = NULL;
        hwAddr = HwMac;
    }
    return hwAddr;
}
std::string get_PartnerId()
{
    char PartnerId[128] = "";
    int dataLen = 0;
    FILE *fp = NULL;
    int ch_count = 0;
    std::string partnerId = "";
    int fd;
    RFC_ParamData_t param = {0};

    fd = open(PARTNERID_FILE, O_RDONLY);
    if (fd != -1)
    {
        fp = fdopen(fd, "r");
        if (fp != NULL)
        {
           fseek(fp, 0, SEEK_END);
           ch_count = ftell(fp);
           if (ch_count < 1)
           {
               printf("Partner ID file is Empty %s\n", PARTNERID_FILE);
               fclose(fp);
           }
           else
           {
                fseek(fp, 0, SEEK_SET);
                size_t bytesRead = fread(PartnerId, 1, ch_count, fp);
	        if (bytesRead != (size_t)ch_count)
	        {
                    printf("Error reading Partner ID, bytes read: %zu\n", bytesRead);
                    fclose(fp);
                    return partnerId;
	        }
                PartnerId[ch_count] = '\0';
	        fclose(fp);
                fp = NULL;
                partnerId = PartnerId;
                printf("[%s:%d]PARTNERID  = [ %s ] \n", __FUNCTION__, __LINE__, PartnerId);
           }
        }
	close(fd);
    } 
    else
    {
        getRFCParameter((char *)"webcfg", PARTNERID, &param);
        dataLen = strlen(param.value);
        if ((dataLen != 0))
        {
            printf("[%s:%d]PARTNERID RFC PARAM VALUE = [ %s ] \n", __FUNCTION__, __LINE__, param.value);
            // remove quotes arround data
            strncpy(PartnerId, &param.value[0], sizeof(PartnerId) - 1);
            PartnerId[sizeof(PartnerId) - 1] = '\0';


        }
    }
    if (!strncmp(PartnerId, UNKNOWN_PARTNERID, sizeof(UNKNOWN_PARTNERID)))
    {
        PartnerId[0] = '\0';
    }
    else
    {
        partnerId = PARTNERID_APPEND;
        partnerId.append(PartnerId);
        printf("[%s:%d]PartnerId = [ %s ] \n", __FUNCTION__, __LINE__, partnerId.c_str());
    }
    if (!partnerId.empty())
    {
        partnerId.erase(std::remove(partnerId.begin(), partnerId.end(), '\n'), partnerId.cend());
    }
    return partnerId;
}

std::string get_RebootReason()
{
    char *rebootReasonFile = NULL;
    FILE *fp = NULL;
    int ch_count = 0;
    std::string reboot_reason = "";
    int fd;

    fd = open(REBOOT_REASON_SECURE_FILE, O_RDONLY);
    if (fd != -1)
    {
        fp = fdopen(fd, "r");
        if (fp != NULL)
        {
           fseek(fp, 0, SEEK_END);
           ch_count = ftell(fp);
           if (ch_count < 1)
           {
              printf("Reboot reason file is Empty %s\n", REBOOT_REASON_SECURE_FILE);
              fclose(fp);
           }
           else
           {
               fseek(fp, 0, SEEK_SET);
               rebootReasonFile = (char *)malloc(sizeof(char) * (ch_count + 1));
               if (rebootReasonFile)
                  {
                  size_t bytesRead = fread(rebootReasonFile, 1, ch_count, fp);
		  if (bytesRead != (size_t)ch_count)
		  {
		     printf("Error reading file, bytes read: %zu\n", bytesRead);
                     free(rebootReasonFile);
                     fclose(fp);
                     return reboot_reason;
		  }
                  rebootReasonFile[ch_count] = '\0';
                  fclose(fp);
                  fp = NULL;

                  // CID:18143 - NEGATIVE RETURNS - since ch_count cannot be negative
                  cJSON *rebootFile = cJSON_Parse(rebootReasonFile);
                  if (rebootFile)
                  {
                      cJSON *reason = NULL;

                      reason = cJSON_GetObjectItem(rebootFile, "reason");
                      if ((NULL != reason && NULL != reason->valuestring))
                      {
                          reboot_reason = reason->valuestring;
                          reboot_reason.erase(std::remove(reboot_reason.begin(), reboot_reason.end(), '\n'), reboot_reason.cend());
                      }
                   }
                   free(rebootReasonFile); // CID:18606 - Resource leak
                  }
               else
               {
                  fclose(fp);
                  fp = NULL;
               }
            }
        }
      close(fd);
    }
    else
    {
        printf("Failed to open reboot reason file %s\n", REBOOT_REASON_SECURE_FILE);
    }
    return reboot_reason;
}

std::string get_FwName()
{
    char imageName[128] = "";
    std::string fw_name = "";
    FILE *fp = fopen(VERSION_FILE, "r");
    if (fp != NULL)
    {
        char line[128] = {'\0'};
        char *token = NULL;
        fgets(line, 128, fp);
        token = strtok(line, ":");
        token = strtok(NULL, ":");
	if (token != NULL) {
            snprintf(imageName, sizeof(imageName), "%s", token); 
        }
        else {
           // Handle the null case if necessary
           printf("Error: Token is null\n");
        }
        fclose(fp);
        fp = NULL;
        fw_name = imageName;
        fw_name.erase(std::remove(fw_name.begin(), fw_name.end(), '\n'), fw_name.cend());
    }
    return fw_name;
}

#ifndef GTEST_ENABLE
int main(int argc, char *argv[])
{
    try
        {
        /*Parameter for the parodus client*/
        std::string webpa_url = "";
        std::string partnerId = "";
        char *manufacturer = NULL;
        char *model = NULL;
        std::string serialNumber = "";
        std::string networkIf = "";
        std::string dnsTextUrl = "";
        std::string tokenServerUrl = "";
        std::string bootTime = "";
        std::string clientCertFile = "";
        int acquireJWT = 0;
        int serverPort = 0;
        int pingWaitTime = 0;
        struct stat status;
        FILE *fp = NULL;
        int ch_count = 0;
        char *webpaCfgFile = NULL;
        RFC_ParamData_t param = {0};
        int dataLen = 0;

        // parodus_Gloop = g_main_loop_new(NULL, FALSE);

        signal(SIGTERM, processExit);
        signal(SIGKILL, processExit);
        signal(SIGABRT, processExit);

        // Get the server IP from RFC parameter
        getRFCParameter((char *)"webcfg", SERVER_IP_URL, &param);
        dataLen = strlen(param.value);
        if (dataLen != 0)
        {
            printf("[%s:%d]SERVER_IP_URL RFC PARAM VALUE = [ %s ] \n", __FUNCTION__, __LINE__, param.value);
            webpa_url = param.value;
        }

        // Get the data from Configuration file
        int fd = open(WEBPA_CFG_OVERIDE_FILE, O_RDONLY);
        if (fd != -1)
        {
            fp = fdopen(fd, "r");
        }
        else
        {
            fd = open(WEBPA_CFG_FILE, O_RDONLY);
            if (fd != -1)
            {
                fp = fdopen(fd, "r");
            }
        }

        if (fp != NULL)
        {
            fseek(fp, 0, SEEK_END);
            ch_count = ftell(fp);

            if (ch_count < 1)
            {
                printf("WebPA config file is Empty %s\n", WEBPA_CFG_FILE);
                fclose(fp);
            }
            else
            {
                fseek(fp, 0, SEEK_SET);
                webpaCfgFile = (char *)malloc(sizeof(char) * (ch_count + 1));

                if (webpaCfgFile)
                {
                    size_t bytesRead = fread(webpaCfgFile, 1, ch_count, fp);
		    if (bytesRead != static_cast<size_t>(ch_count))
                    {
                     printf("Error reading WebPA config file, bytes read: %zu\n", bytesRead);
                     free(webpaCfgFile);
                     fclose(fp);
		     close(fd);
                     return 1; // or handle the error as needed
		    }
                 
                    webpaCfgFile[ch_count] = '\0';
                    // CID:18143 - NEGATIVE RETURNS - since ch_count cannot be negative
                    cJSON *webpa_cfg = cJSON_Parse(webpaCfgFile);
                    if (webpa_cfg)
                    {
                        cJSON *serverIp = NULL;
                        cJSON *aJwt = NULL;
                        cJSON *DeviceNwkIf = NULL;
                        cJSON *srvrPort = NULL;
                        cJSON *MaxPingWaitTimeInSec = NULL;

                        serverIp = cJSON_GetObjectItem(webpa_cfg, "ServerIP");
                        aJwt = cJSON_GetObjectItem(webpa_cfg, "acquire-jwt");
                        DeviceNwkIf = cJSON_GetObjectItem(webpa_cfg, "DeviceNetworkInterface");
                        srvrPort = cJSON_GetObjectItem(webpa_cfg, "ServerPort");
                        MaxPingWaitTimeInSec = cJSON_GetObjectItem(webpa_cfg, "MaxPingWaitTimeInSec");

                        if ((NULL != serverIp && NULL != serverIp->valuestring) && (webpa_url.empty()))
                        {
                            // strncpy(ServerIP,serverIp->valuestring,strlen(serverIp->valuestring));
                            // printf("[%s:%d]ServerIP = [ %s ] \n", __FUNCTION__, __LINE__, ServerIP);
                            webpa_url = serverIp->valuestring;
                        }

                        if ((NULL != aJwt))
                        {
                            acquireJWT = aJwt->valueint;
                            printf("acquireJWT = [ %d ] \n", acquireJWT);
                        }

                        if ((NULL != DeviceNwkIf && NULL != DeviceNwkIf->valuestring))
                        {
                            networkIf = DeviceNwkIf->valuestring;
                            printf("NetworkIF = [ %s] \n", networkIf.c_str());
                        }

                        if ((NULL != srvrPort))
                        {
                            serverPort = srvrPort->valueint;
                            printf("serverPort = [ %d ] \n", serverPort);
                        }

                        if ((NULL != MaxPingWaitTimeInSec))
                        {
                            pingWaitTime = MaxPingWaitTimeInSec->valueint;
                            printf("pingWaitTime = [ %d ] \n", pingWaitTime);
                        }
                    }
                    free(webpaCfgFile); // CID:18606 - Resource leak
                    if (fp)
                    {
                        fclose(fp);
                        fp = NULL;
                    }
                }
                else
                {
                    fclose(fp);
                    fp = NULL;
                }
            }
        }
        else
        {
            printf("Failed to open Webpa cfg file %s\n", WEBPA_CFG_FILE);
        }

    #ifdef RDKCLISSA
        getDeviceConfigFile();
    #endif

        // Getting Webpa Parameters
        // Get "Device.X_RDK_WebPA_DNSText.URL"
        getRFCParameter((char *)"webcfg", DNS_TEXT_URL, &param);
        dataLen = strlen(param.value);
        if (dataLen != 0)
        {
            printf("[%s:%d]DNS_TEXT_URL RFC PARAM VALUE = [ %s ] \n", __FUNCTION__, __LINE__, param.value);
            dnsTextUrl = param.value;
        }

        // X_RDK_WebPA_TokenServer
        getRFCParameter((char *)"webcfg", TOKEN_SERVER_URL, &param);
        dataLen = strlen(param.value);
        if (dataLen != 0)
        {
            printf("[%s:%d]TOKEN_SERVER_URL RFC PARAM VALUE = [ %s ] \n", __FUNCTION__, __LINE__, param.value);
            // remove quotes arround data
            tokenServerUrl = param.value;
        }

        // Manufacturer
        manufacturer = getenv("MANUFACTURE");

        // Model Number
        model = getenv("MODEL_NUM");

        // Partner ID
        partnerId = get_PartnerId();

        // Reboot reason
        std::string reboot_reason = get_RebootReason();

        /*Get HW MAc Address*/
        std::string hw_addr = get_HWMAcAddress();

        // Image Name
        std::string fw_name = get_FwName();

        // Serial Number
        getRFCParameter((char *)"webcfg", SERIAL_NUMBER, &param);
        dataLen = strlen(param.value);
        if (dataLen != 0)
        {
            printf("[%s:%d] SERIAL_NUMBER RFC PARAM VALUE = [ %s ] \n", __FUNCTION__, __LINE__, param.value);
            serialNumber = param.value;
        }

        // get_Boottime
        getRFCParameter((char *)"webcfg", BOOT_TIME, &param);
        dataLen = strlen(param.value);
        if (dataLen != 0)
        {
            printf("[%s:%d]BOOT_TIME RFC PARAM VALUE = [ %s ] \n", __FUNCTION__, __LINE__, param.value);
            bootTime = param.value;
        }

        // Config File check
        if ((stat(CONFIG_RES_FILE, &status) == 0))
        {
            clientCertFile = CONFIG_RES_FILE;
        }
        // Starting Parodus
        printf("Parodus Process satrting with Arguments: = [ /usr/bin/parodus \
        --hw-mac=%s --webpa-ping-time=%d --webpa-interface-used=%s --webpa-url=%s \
        --partner-id=%s --webpa-backoff-max=9 --ssl-cert-path=%s --acquire-jwt=%d \
        --dns-txt-url=%s --jwt-public-key-file=%s --jwt-algo=RS256 --record-jwt-payload=%s \
        --crud-config-file=%s --hw-manufacturer=%s --fw-name=%s --hw-model=%s \
        --hw-serial-number=%s --boot-time=%s --hw-last-reboot-reason=\"%s\" --client-cert-path=%s --token-server-url=%s & ]\n",
               hw_addr.c_str(), pingWaitTime, networkIf.c_str(), webpa_url.c_str(),
               partnerId.c_str(), SSL_CERT_FILE, acquireJWT,
               dnsTextUrl.c_str(), JWT_KEY, RECORD_JWT_PAYLOAD_FILE,
               CRUD_CONFIG_FILE, manufacturer, fw_name.c_str(), model,
               serialNumber.c_str(), bootTime.c_str(), reboot_reason.c_str(), clientCertFile.c_str(), tokenServerUrl.c_str());

        v_secure_system("backgroundrun /usr/bin/parodus \
        --hw-mac=%s --webpa-ping-time=%d --webpa-interface-used=%s --webpa-url=%s \
        --partner-id=%s --webpa-backoff-max=9 --ssl-cert-path=%s  --acquire-jwt=%d \
        --dns-txt-url=%s --jwt-public-key-file=%s --jwt-algo=RS256 --record-jwt-payload=%s \
        --crud-config-file=%s  --hw-manufacturer=%s --fw-name=%s --hw-model=%s \
        --hw-serial-number=%s --boot-time=%s --hw-last-reboot-reason=\"%s\" --client-cert-path=%s --token-server-url=%s",
                        hw_addr.c_str(), pingWaitTime, networkIf.c_str(), webpa_url.c_str(),
                        partnerId.c_str(), SSL_CERT_FILE, acquireJWT,
                        dnsTextUrl.c_str(), JWT_KEY, RECORD_JWT_PAYLOAD_FILE,
                       CRUD_CONFIG_FILE, manufacturer, fw_name.c_str(), model,
                       serialNumber.c_str(), bootTime.c_str(), reboot_reason.c_str(), clientCertFile.c_str(), tokenServerUrl.c_str());


   }
    catch (const std::bad_cast& e)
     {
        std::cerr << "Bad cast exception: " << e.what() << std::endl;
        return 1;
     }
     catch (const std::exception& e)
     {
         std::cerr << "Exception: " << e.what() << std::endl;
         return 1;
     }
     catch (...)
     {
         std::cerr << "Unknown exception occurred" << std::endl;
         return 1;
     }
       	
 
  
return 0;
}
#endif
