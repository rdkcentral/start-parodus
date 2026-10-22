/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2024 RDK Management
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

#include <fcntl.h>
#include <unistd.h>
#include "start_parodus_mock.h"

using namespace std;
using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::SetArrayArgument;
using ::testing::Invoke;

extern "C"
{
#include "cJSON.h"
#include "start_parodus.h"
void waitForPSMHealth(const char *compName);
int numLoops = 1;
}

#define MAX_PARTNERID_LEN              64

extern SafecLibMock * g_safecLibMock;
extern SyscfgMock * g_syscfgMock;
extern PlatformHalMock * g_platformHALMock;
extern utopiaMock * g_utopiaMock;
extern SyseventMock * g_syseventMock;
extern CmHalMock * g_cmHALMock;
extern cjsonMock *g_cjsonMock;
extern FileIOMock *g_fileIOMock;

// In-file Fopen Mock implementation
class FopenMock {
public:
    MOCK_METHOD(FILE*, fopen_mock, (const char* filename, const char* mode), ());
};

FopenMock* g_fopenMock = nullptr;

extern "C" FILE* fopen_mock(const char* filename, const char* mode)
{
    if (g_fopenMock) {
        return g_fopenMock->fopen_mock(filename, mode);
    }
    return std::fopen(filename, mode);
}

class StartParodusTestFixture : public StartParodusBaseTestFixture {
protected:
    void SetUp() {
        g_fopenMock = new FopenMock();
        numLoops = 1;
    }

    void TearDown() {
        delete g_fopenMock;
        g_fopenMock = nullptr;
    }
};

static errno_t strcpy_s_success(char* dest, size_t destSize, const char* src, size_t srcSize)
{
    strncpy(dest, src, destSize);
    return 0;
}

static int sprintf_s_success(char* dest, size_t destSize, size_t n, const char* formatted)
{
    strncpy(dest, formatted, destSize);
    return strlen(dest);
}

// buildParodusCommand
TEST_F(StartParodusTestFixture, buildParodusCommand_Success)
{
    char command[2048] = {'\0'};
    ParodusCommandConfig config = {};
    config.modelName = "TestModel";
    config.serialNumber = "TestSerial";
    config.manufacturer = "TestManufacturer";
    config.lastRebootReason = "PowerOn";
    config.firmwareVersion = "1.2.3";
    config.bootTime = 123;
    config.deviceMac = "00:11:22:33:44:55";
    config.webpaInterface = "erouter0";
    config.webpaUrl = "https://webpa.example";
    config.webpaPingTime = 180;
    config.parodusUrl = "tcp://parodus.example:6666";
    config.partnerId = "*,comcast";
    config.clientCertPath = "/nvram/certs/devicecert_1.pk12";
    config.sslEngine = "NA";
    config.sslCertType = "P12";
    config.sslReferenceName = "/tmp/.cfgDynamicxpki";
    config.tokenServerUrl = "https://token.example";
    config.bootTimeRetryWait = 5;

    int ret = buildParodusCommand(command, sizeof(command), &config);
    EXPECT_EQ(0, ret);
    EXPECT_NE(strstr(command, "--hw-model=\"TestModel\""), nullptr);
    EXPECT_NE(strstr(command, "--hw-serial-number=TestSerial"), nullptr);
    EXPECT_NE(strstr(command, "--hw-mac=00:11:22:33:44:55"), nullptr);
    EXPECT_NE(strstr(command, "--webpa-url=https://webpa.example"), nullptr);
    EXPECT_NE(strstr(command, "--parodus-local-url=tcp://parodus.example:6666"), nullptr);
    EXPECT_NE(strstr(command, "--partner-id=*,comcast"), nullptr);
    EXPECT_NE(strstr(command, "--client-cert-path=/nvram/certs/devicecert_1.pk12"), nullptr);
    EXPECT_NE(strstr(command, "--token-server-url=https://token.example"), nullptr);
    EXPECT_NE(strstr(command, "--boot-time-retry-wait=5"), nullptr);
}

TEST_F(StartParodusTestFixture, buildParodusCommand_DefaultParodusUrl)
{
    char command[2048] = {'\0'};
    ParodusCommandConfig config = {};

    int ret = buildParodusCommand(command, sizeof(command), &config);
    EXPECT_EQ(0, ret);
    EXPECT_NE(strstr(command, "--parodus-local-url=tcp://127.0.0.1:6666"), nullptr);
}

TEST_F(StartParodusTestFixture, buildParodusCommand_InvalidArgs)
{
    char command[2048] = {'\0'};
    ParodusCommandConfig config = {};

    EXPECT_EQ(-1, buildParodusCommand(nullptr, sizeof(command), &config));
    EXPECT_EQ(-1, buildParodusCommand(command, 0, &config));
    EXPECT_EQ(-1, buildParodusCommand(command, sizeof(command), nullptr));
}

TEST_F(StartParodusTestFixture, buildParodusCommand_BufferTooSmall)
{
    char command[8] = {'\0'};
    ParodusCommandConfig config = {};

    EXPECT_EQ(-1, buildParodusCommand(command, sizeof(command), &config));
}

// publishParodusCommand
TEST_F(StartParodusTestFixture, publishParodusCommand_NullCommand)
{
    EXPECT_EQ(-1, publishParodusCommand(nullptr));
}

TEST_F(StartParodusTestFixture, publishParodusCommand_Success)
{
    const char expected_command[] = "TestCommand";
    char buffer[100] = {0};

    // fclose is mocked, so flush the stream to get the command into the file.
    EXPECT_CALL(*g_fileIOMock, fclose(_))
        .Times(1)
        .WillOnce(Invoke([](FILE* stream) {
            fflush(stream);
            close(fileno(stream));
            return 0;
        }));

    int ret = publishParodusCommand(expected_command);
    EXPECT_EQ(0, ret);

    int fd = open("/tmp/parodusCmd.cmd", O_RDONLY);
    ASSERT_GE(fd, 0);
    ASSERT_GT(read(fd, buffer, sizeof(buffer) - 1), 0);
    close(fd);
    remove("/tmp/parodusCmd.cmd");
    EXPECT_STREQ(buffer, expected_command);
}

// getPartnerId
TEST_F(StartParodusTestFixture, getPartnerId_PartnerIdExists)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    const char* expected_partner_id = "TEST_PARTNER_ID";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(
            SetArrayArgument<2>(expected_partner_id, expected_partner_id + strlen(expected_partner_id) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke(sprintf_s_success));

    int ret = getPartnerId(partner_id, sizeof(partner_id));
    EXPECT_EQ(0, ret);
    EXPECT_STREQ(partner_id, "*,TEST_PARTNER_ID");
}

TEST_F(StartParodusTestFixture, getPartnerId_UnknownPartnerId)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    const char* expected_partner_id = "unknown";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(
            SetArrayArgument<2>(expected_partner_id, expected_partner_id + strlen(expected_partner_id) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    int ret = getPartnerId(partner_id, sizeof(partner_id));
    EXPECT_EQ(0, ret);
    EXPECT_STREQ(partner_id, "");
}

TEST_F(StartParodusTestFixture, getPartnerId_new_partnerID_Successful_get)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(Return(1));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, mockFile))
        .Times(1)
        .WillOnce(DoAll(
            ::testing::WithArg<0>(Invoke([](char* buf) {
                strcpy(buf, "TEST_PARTNER_ID\n");
            })),
            Return(reinterpret_cast<char*>(1))
        ));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke(sprintf_s_success));

    int ret = getPartnerId(partner_id, sizeof(partner_id));
    EXPECT_EQ(0, ret);
    EXPECT_STREQ(partner_id, "*,TEST_PARTNER_ID");
}

TEST_F(StartParodusTestFixture, getPartnerId_popen_Fail)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(Return(1));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    int ret = getPartnerId(partner_id, sizeof(partner_id));
    EXPECT_EQ(-1, ret);
    EXPECT_STREQ(partner_id, "");
}

TEST_F(StartParodusTestFixture, getPartnerId_fgets_error)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(Return(1));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, mockFile))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    int ret = getPartnerId(partner_id, sizeof(partner_id));
    EXPECT_EQ(-1, ret);
}

TEST_F(StartParodusTestFixture, getPartnerId_InvalidBuffer)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};

    EXPECT_EQ(-1, getPartnerId(nullptr, sizeof(partner_id)));
    EXPECT_EQ(-1, getPartnerId(partner_id, 0));
}

// get_url
TEST_F(StartParodusTestFixture, get_url_Fopen_error)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
    char build_type[16] = {'\0'};

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, "");
    EXPECT_STREQ(seshat_url, "");
    EXPECT_STREQ(build_type, "");
}

TEST_F(StartParodusTestFixture, get_url_GET_ALL)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
    char build_type[16] = {'\0'};

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(4)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=test_parodus_url");
            return 1;
        }))
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SESHAT_URL=test_seshat_url");
            return 1;
        }))
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "BUILD_TYPE=prod");
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, "test_parodus_url");
    EXPECT_STREQ(seshat_url, "test_seshat_url");
    EXPECT_STREQ(build_type, "prod");
}

TEST_F(StartParodusTestFixture, get_url_parodus_url_strcpy_Fail)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
    char build_type[16] = {'\0'};

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(1)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=test_parodus_url");
            return 1;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, "");
}

// getAcquireJwt
TEST_F(StartParodusTestFixture, getAcquireJwt_CfgFile_Fail)
{
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_EQ(1, getAcquireJwt());
}

// getWebpaPingTime
TEST_F(StartParodusTestFixture, getWebpaPingTime_Default)
{
    EXPECT_EQ(180, getWebpaPingTime());
}

// getClientCertPath
TEST_F(StartParodusTestFixture, getClientCertPath_Success)
{
    char client_cert_path[128] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getClientCertPath(1, client_cert_path, sizeof(client_cert_path)));
    EXPECT_STREQ(client_cert_path, "/nvram/certs/devicecert_2.pk12");
    EXPECT_EQ(0, getClientCertPath(2, client_cert_path, sizeof(client_cert_path)));
    EXPECT_STREQ(client_cert_path, "/nvram/certs/devicecert_1.pk12");
    EXPECT_EQ(0, getClientCertPath(3, client_cert_path, sizeof(client_cert_path)));
    EXPECT_STREQ(client_cert_path, "/etc/ssl/certs/staticXpkiCrt.pk12");
}

TEST_F(StartParodusTestFixture, getClientCertPath_InvalidDecodeStatus)
{
    char client_cert_path[128] = {'\0'};

    EXPECT_EQ(-1, getClientCertPath(-1, client_cert_path, sizeof(client_cert_path)));
    EXPECT_EQ(-1, getClientCertPath(1, nullptr, sizeof(client_cert_path)));
    EXPECT_EQ(-1, getClientCertPath(1, client_cert_path, 0));
}

TEST_F(StartParodusTestFixture, getClientCertPath_strcpy_Fail)
{
    char client_cert_path[128] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getClientCertPath(2, client_cert_path, sizeof(client_cert_path)));
}

// getSslReferenceName
TEST_F(StartParodusTestFixture, getSslReferenceName_Success)
{
    char ssl_reference_name[128] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getSslReferenceName(1, ssl_reference_name, sizeof(ssl_reference_name)));
    EXPECT_STREQ(ssl_reference_name, "/tmp/.cfgDynamicSExpki");
    EXPECT_EQ(0, getSslReferenceName(2, ssl_reference_name, sizeof(ssl_reference_name)));
    EXPECT_STREQ(ssl_reference_name, "/tmp/.cfgDynamicxpki");
    EXPECT_EQ(0, getSslReferenceName(3, ssl_reference_name, sizeof(ssl_reference_name)));
    EXPECT_STREQ(ssl_reference_name, "/tmp/.cfgStaticxpki");
}

TEST_F(StartParodusTestFixture, getSslReferenceName_InvalidDecodeStatus)
{
    char ssl_reference_name[128] = {'\0'};

    EXPECT_EQ(-1, getSslReferenceName(-1, ssl_reference_name, sizeof(ssl_reference_name)));
    EXPECT_EQ(-1, getSslReferenceName(1, nullptr, sizeof(ssl_reference_name)));
    EXPECT_EQ(-1, getSslReferenceName(1, ssl_reference_name, 0));
}

// getSslEngine
TEST_F(StartParodusTestFixture, getSslEngine_SECert)
{
    char ssl_engine[32] = "NA";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getSslEngine("/nvram/certs/devicecert_2.pk12", ssl_engine, sizeof(ssl_engine)));
    EXPECT_STREQ(ssl_engine, "e4sss");
}

TEST_F(StartParodusTestFixture, getSslEngine_NonSECert)
{
    char ssl_engine[32] = "NA";

    EXPECT_EQ(0, getSslEngine("/nvram/certs/devicecert_1.pk12", ssl_engine, sizeof(ssl_engine)));
    EXPECT_STREQ(ssl_engine, "NA");
}

TEST_F(StartParodusTestFixture, getSslEngine_InvalidArgs)
{
    char ssl_engine[32] = "NA";

    EXPECT_EQ(-1, getSslEngine(nullptr, ssl_engine, sizeof(ssl_engine)));
    EXPECT_EQ(-1, getSslEngine("/nvram/certs/devicecert_2.pk12", nullptr, sizeof(ssl_engine)));
}

// getSslCertType
TEST_F(StartParodusTestFixture, getSslCertType_Success)
{
    char ssl_cert_type[8] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getSslCertType(ssl_cert_type, sizeof(ssl_cert_type)));
    EXPECT_STREQ(ssl_cert_type, "P12");
}

TEST_F(StartParodusTestFixture, getSslCertType_strcpy_Fail)
{
    char ssl_cert_type[8] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getSslCertType(ssl_cert_type, sizeof(ssl_cert_type)));
}

// getWebpaInterface
TEST_F(StartParodusTestFixture, getWebpaInterface_Success)
{
    char webpa_interface[64] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getWebpaInterface(webpa_interface, sizeof(webpa_interface)));
    EXPECT_STREQ(webpa_interface, "erouter0");
}

TEST_F(StartParodusTestFixture, getWebpaInterface_InvalidArgs)
{
    char webpa_interface[64] = {'\0'};

    EXPECT_EQ(-1, getWebpaInterface(nullptr, sizeof(webpa_interface)));
    EXPECT_EQ(-1, getWebpaInterface(webpa_interface, 0));
}

// getDeviceMac
TEST_F(StartParodusTestFixture, getDeviceMac_InvalidArgs)
{
    char device_mac[32] = {'\0'};

    EXPECT_EQ(-1, getDeviceMac(nullptr, sizeof(device_mac)));
    EXPECT_EQ(-1, getDeviceMac(device_mac, 0));
}

// getWebpaConfig
TEST_F(StartParodusTestFixture, getWebpaConfig_InvalidArgs)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    EXPECT_EQ(-1, getWebpaConfig("prod", nullptr, nullptr, &token_server_url, &dns_text_url));
    EXPECT_EQ(-1, getWebpaConfig("prod", nullptr, &webpa_url, nullptr, &dns_text_url));
    EXPECT_EQ(-1, getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, nullptr));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_NoServerUrl)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    int ret = getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, &dns_text_url);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(webpa_url, nullptr);
    EXPECT_EQ(token_server_url, nullptr);
    EXPECT_EQ(dns_text_url, nullptr);
}

TEST_F(StartParodusTestFixture, getWebpaConfig_FromPartnerJson)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    const char* json_content = R"({
        "comcast": {
            "Device.X_RDKCENTRAL-COM_Webpa.Server.URL": "https://webpa.comcast.net:8080",
            "Device.X_RDKCENTRAL-COM_Webpa.TokenServer.URL": "https://token.comcast.net:8080",
            "Device.X_RDKCENTRAL-COM_Webpa.DNSText.URL": "https://dns.comcast.net"
        }
    })";
    size_t json_size = strlen(json_content);

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    cJSON mockJsonRoot = {};
    cJSON mockPartnerObj = {};
    cJSON mockWebpaItem = {};
    cJSON mockTokenItem = {};
    cJSON mockDnsItem = {};
    mockWebpaItem.type = cJSON_String;
    mockWebpaItem.valuestring = (char *)"https://webpa.comcast.net:8080";
    mockTokenItem.type = cJSON_String;
    mockTokenItem.valuestring = (char *)"https://token.comcast.net:8080";
    mockDnsItem.type = cJSON_String;
    mockDnsItem.valuestring = (char *)"https://dns.comcast.net";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/partners_defaults.json"), StrEq("r")))
        .Times(3)
        .WillRepeatedly(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, _))
        .Times(6)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(3)
        .WillRepeatedly(Return(json_size));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, json_size, mockFile))
        .Times(3)
        .WillRepeatedly(Invoke([json_content, json_size](void* ptr, size_t size, size_t nmemb, FILE* stream) {
            memcpy(ptr, json_content, json_size);
            return json_size;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(3)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(3)
        .WillRepeatedly(Return(&mockJsonRoot));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&mockPartnerObj))
        .WillOnce(Return(&mockWebpaItem))
        .WillOnce(Return(&mockPartnerObj))
        .WillOnce(Return(&mockTokenItem))
        .WillOnce(Return(&mockPartnerObj))
        .WillOnce(Return(&mockDnsItem));

    EXPECT_CALL(*g_cjsonMock, cJSON_IsString(_))
        .Times(3)
        .WillRepeatedly(Return(1));

    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(3);

    int ret = getWebpaConfig("prod", "*,comcast", &webpa_url, &token_server_url, &dns_text_url);
    EXPECT_EQ(0, ret);
    EXPECT_STREQ(webpa_url, "https://webpa.comcast.net:8080");
    EXPECT_STREQ(token_server_url, "https://token.comcast.net:8080");
    EXPECT_STREQ(dns_text_url, "https://dns.comcast.net");

    free(webpa_url);
    free(token_server_url);
    free(dns_text_url);
}

// waitForPSMHealth
TEST_F(StartParodusTestFixture, waitForPSMHealth_Fail)
{
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    waitForPSMHealth("Test_Component");
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_SPRINTF_Fail)
{
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke(sprintf_s_success))
        .WillOnce(Return(-1));

    waitForPSMHealth("Test_Component");
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_Green_First)
{
    FILE *output = reinterpret_cast<FILE *>(1);

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(output));
    EXPECT_CALL(*g_fileIOMock, fscanf(output, _, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    waitForPSMHealth("Test_Component");
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_Popen_Fail)
{
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));

    waitForPSMHealth("Test_Component");
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_Green_After_a_Retry)
{
    numLoops = 2;
    FILE *output = reinterpret_cast<FILE *>(1);

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(2)
        .WillRepeatedly(Return(output));
    EXPECT_CALL(*g_fileIOMock, fscanf(output, _, _))
        .Times(2)
        .WillRepeatedly(Return(1));
    EXPECT_CALL(*g_fileIOMock, pclose(output))
        .Times(2)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(1), Return(0)))
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    waitForPSMHealth("Test_Component");
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_Never_Green)
{
    numLoops = 7;
    FILE *output = reinterpret_cast<FILE *>(1);

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(8)
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(7)
        .WillRepeatedly(Return(output));
    EXPECT_CALL(*g_fileIOMock, fscanf(output, _, _))
        .Times(7)
        .WillRepeatedly(Return(1));
    EXPECT_CALL(*g_fileIOMock, pclose(output))
        .Times(7)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(7)
        .WillRepeatedly(DoAll(SetArgPointee<3>(1), Return(0)));

    waitForPSMHealth("Test_Component");
}

