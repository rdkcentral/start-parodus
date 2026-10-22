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
#include <sys/stat.h>
#include <string>
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
char *getWebpaUrl(const char *buildType);
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

static errno_t strcmp_s_real(const char* dest, size_t dmax, const char* src, int* result,
                             size_t destbos, size_t srcbos)
{
    *result = strcmp(dest, src);
    return 0;
}

static void expectCfgFileReads(const char *path, FILE *file, const char *json, int reads)
{
    size_t len = strlen(json);

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq(path), StrEq("r")))
        .Times(reads)
        .WillRepeatedly(Return(file));
    EXPECT_CALL(*g_fileIOMock, fseek(file, 0, _))
        .Times(2 * reads)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, ftell(file))
        .Times(reads)
        .WillRepeatedly(Return(static_cast<long>(len)));
    EXPECT_CALL(*g_fileIOMock, fread(_, 1, len, file))
        .Times(reads)
        .WillRepeatedly(Invoke([json, len](void *ptr, size_t size, size_t nmemb, FILE *stream) {
            memcpy(ptr, json, len);
            return len;
        }));
    EXPECT_CALL(*g_fileIOMock, fclose(file))
        .Times(reads)
        .WillRepeatedly(Return(0));
}

static void expectJsonTypeChecks()
{
    EXPECT_CALL(*g_cjsonMock, cJSON_IsString(_))
        .WillRepeatedly(Invoke([](const cJSON *item) { return item->type == cJSON_String ? 1 : 0; }));
    EXPECT_CALL(*g_cjsonMock, cJSON_IsNumber(_))
        .WillRepeatedly(Invoke([](const cJSON *item) { return item->type == cJSON_Number ? 1 : 0; }));
}

static bool fileExists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool createFile(const char *path)
{
    mkdir("/nvram", 0755);
    mkdir("/nvram/certs", 0755);
    mkdir("/etc/ssl", 0755);
    mkdir("/etc/ssl/certs", 0755);
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

#define SE_DEVICE_CERT_PATH  "/nvram/certs/devicecert_2.pk12"
#define DEVICE_CERT_PATH     "/nvram/certs/devicecert_1.pk12"
#define STATIC_CERT_PATH     "/etc/ssl/certs/staticXpkiCrt.pk12"

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

// handle_wan_status
TEST_F(StartParodusTestFixture, handle_wan_status_NoArgs)
{
    char *argv[] = {(char *)"parodusStart", nullptr};

    EXPECT_EQ(0, handle_wan_status(1, argv));
}

TEST_F(StartParodusTestFixture, handle_wan_status_OtherArg)
{
    char *argv[] = {(char *)"parodusStart", (char *)"other", nullptr};

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcmp_s_real));

    EXPECT_EQ(0, handle_wan_status(2, argv));
}

TEST_F(StartParodusTestFixture, handle_wan_status_NotStarted)
{
    char *argv[] = {(char *)"parodusStart", (char *)"wan-status", (char *)"stopped", nullptr};

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_fileIOMock, fclose(_))
        .WillRepeatedly(Return(0));

    EXPECT_EQ(1, handle_wan_status(3, argv));
}

TEST_F(StartParodusTestFixture, handle_wan_status_Started_popen_Fail)
{
    char *argv[] = {(char *)"parodusStart", (char *)"wan-status", (char *)"started", nullptr};

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_EQ(1, handle_wan_status(3, argv));
}

TEST_F(StartParodusTestFixture, handle_wan_status_Started_ParodusRunning)
{
    char *argv[] = {(char *)"parodusStart", (char *)"wan-status", (char *)"started", nullptr};
    FILE *output = reinterpret_cast<FILE *>(1);

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(output));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, output))
        .Times(1)
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "1234\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_fileIOMock, pclose(output))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(1, handle_wan_status(3, argv));
}

TEST_F(StartParodusTestFixture, handle_wan_status_Started_ParodusNotRunning)
{
    char *argv[] = {(char *)"parodusStart", (char *)"wan-status", (char *)"started", nullptr};
    FILE *output = reinterpret_cast<FILE *>(1);

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(output));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, output))
        .Times(1)
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_fileIOMock, pclose(output))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(0, handle_wan_status(3, argv));
}

// init_hal_db
TEST_F(StartParodusTestFixture, init_hal_db_Success)
{
    EXPECT_CALL(*g_platformHALMock, platform_hal_PandMDBInit())
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_cmHALMock, cm_hal_InitDB())
        .Times(1)
        .WillOnce(Return(0));

    init_hal_db();
}

TEST_F(StartParodusTestFixture, init_hal_db_Failure)
{
    EXPECT_CALL(*g_platformHALMock, platform_hal_PandMDBInit())
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_cmHALMock, cm_hal_InitDB())
        .Times(1)
        .WillOnce(Return(-1));

    init_hal_db();
}

// startParodusProcess
TEST_F(StartParodusTestFixture, startParodusProcess_Default)
{
    EXPECT_EQ(0, startParodusProcess("TestCommand"));
}

// getDeviceMac
TEST_F(StartParodusTestFixture, getDeviceMac_SyseventConnect_Fail)
{
    char device_mac[32] = {'\0'};

    EXPECT_CALL(*g_utopiaMock, s_sysevent_connect(_))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getDeviceMac(device_mac, sizeof(device_mac)));
}

TEST_F(StartParodusTestFixture, getDeviceMac_EthWanEnabled)
{
    char device_mac[32] = {'\0'};
    const char *eth_enabled = "true";
    const char *eth_mac = "aa:bb:cc:dd:ee:ff";

    EXPECT_CALL(*g_utopiaMock, s_sysevent_connect(_))
        .Times(1)
        .WillOnce(Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("eth_wan_enabled"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(eth_enabled, eth_enabled + strlen(eth_enabled) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("eth_wan_mac"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<3>(eth_mac, eth_mac + strlen(eth_mac) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getDeviceMac(device_mac, sizeof(device_mac)));
    EXPECT_STREQ(device_mac, eth_mac);
}

TEST_F(StartParodusTestFixture, getDeviceMac_FromDhcpInfo)
{
    char device_mac[32] = {'\0'};

    EXPECT_CALL(*g_utopiaMock, s_sysevent_connect(_))
        .Times(1)
        .WillOnce(Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("eth_wan_enabled"), _, _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_cmHALMock, cm_hal_GetDHCPInfo(_))
        .Times(1)
        .WillOnce(Invoke([](PCMMGMT_CM_DHCP_INFO pInfo) {
            strcpy(pInfo->MACAddress, "00:11:22:33:44:55");
            return 0;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getDeviceMac(device_mac, sizeof(device_mac)));
    EXPECT_STREQ(device_mac, "00:11:22:33:44:55");
}

// strcpy_s failures
TEST_F(StartParodusTestFixture, getSslReferenceName_strcpy_Fail)
{
    char ssl_reference_name[128] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getSslReferenceName(2, ssl_reference_name, sizeof(ssl_reference_name)));
}

TEST_F(StartParodusTestFixture, getSslEngine_strcpy_Fail)
{
    char ssl_engine[32] = "NA";

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getSslEngine("/nvram/certs/devicecert_2.pk12", ssl_engine, sizeof(ssl_engine)));
}

TEST_F(StartParodusTestFixture, getWebpaInterface_strcpy_Fail)
{
    char webpa_interface[64] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getWebpaInterface(webpa_interface, sizeof(webpa_interface)));
}

TEST_F(StartParodusTestFixture, getPartnerId_strcpy_Fail)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    const char *configured_partner_id = "comcast";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(configured_partner_id,
                                            configured_partner_id + strlen(configured_partner_id) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getPartnerId(partner_id, sizeof(partner_id)));
}

TEST_F(StartParodusTestFixture, getPartnerId_sprintf_Fail)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    const char *configured_partner_id = "comcast";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(configured_partner_id,
                                            configured_partner_id + strlen(configured_partner_id) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getPartnerId(partner_id, sizeof(partner_id)));
}

// getModelName / getSerialNumber / getFirmwareName
TEST_F(StartParodusTestFixture, getModelName_Success)
{
    char model_name[64] = {'\0'};

    EXPECT_CALL(*g_platformHALMock, platform_hal_GetModelName(_))
        .Times(1)
        .WillOnce(Invoke([](CHAR *value) {
            strcpy(value, "TestModel");
            return 0;
        }));

    getModelName(model_name, sizeof(model_name));
    EXPECT_STREQ(model_name, "TestModel");
}

TEST_F(StartParodusTestFixture, getModelName_Fail)
{
    char model_name[64] = "stale";

    EXPECT_CALL(*g_platformHALMock, platform_hal_GetModelName(_))
        .Times(1)
        .WillOnce(Return(-1));

    getModelName(model_name, sizeof(model_name));
    EXPECT_STREQ(model_name, "");
    getModelName(nullptr, sizeof(model_name));
}

TEST_F(StartParodusTestFixture, getSerialNumber_Success)
{
    char serial_number[64] = {'\0'};

    EXPECT_CALL(*g_platformHALMock, platform_hal_GetSerialNumber(_))
        .Times(1)
        .WillOnce(Invoke([](CHAR *value) {
            strcpy(value, "TestSerial");
            return 0;
        }));

    getSerialNumber(serial_number, sizeof(serial_number));
    EXPECT_STREQ(serial_number, "TestSerial");
}

TEST_F(StartParodusTestFixture, getSerialNumber_Fail)
{
    char serial_number[64] = "stale";

    EXPECT_CALL(*g_platformHALMock, platform_hal_GetSerialNumber(_))
        .Times(1)
        .WillOnce(Return(-1));

    getSerialNumber(serial_number, sizeof(serial_number));
    EXPECT_STREQ(serial_number, "");
    getSerialNumber(nullptr, sizeof(serial_number));
}

TEST_F(StartParodusTestFixture, getFirmwareName_Success)
{
    char firmware_name[64] = {'\0'};

    EXPECT_CALL(*g_platformHALMock, platform_hal_GetFirmwareName(_, _))
        .Times(1)
        .WillOnce(Invoke([](CHAR *value, ULONG size) {
            strncpy(value, "TestFirmware", size);
            return 0;
        }));

    getFirmwareName(firmware_name, sizeof(firmware_name));
    EXPECT_STREQ(firmware_name, "TestFirmware");
}

TEST_F(StartParodusTestFixture, getFirmwareName_Fail)
{
    char firmware_name[64] = "stale";

    EXPECT_CALL(*g_platformHALMock, platform_hal_GetFirmwareName(_, _))
        .Times(1)
        .WillOnce(Return(-1));

    getFirmwareName(firmware_name, sizeof(firmware_name));
    EXPECT_STREQ(firmware_name, "");
    getFirmwareName(nullptr, sizeof(firmware_name));
}

// getManufacturer
TEST_F(StartParodusTestFixture, getManufacturer_Success)
{
    char manufacturer[64] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));

    getManufacturer(manufacturer, sizeof(manufacturer));
    EXPECT_STRNE(manufacturer, "");
}

TEST_F(StartParodusTestFixture, getManufacturer_strcpy_Fail)
{
    char manufacturer[64] = {'\0'};

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    getManufacturer(manufacturer, sizeof(manufacturer));
    EXPECT_STREQ(manufacturer, "");
    getManufacturer(nullptr, sizeof(manufacturer));
}

// getRebootReason
TEST_F(StartParodusTestFixture, getRebootReason_CounterZero_FileMissing)
{
    char reason[128] = {'\0'};
    const char *counter = "0";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_LastRebootCounter"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(counter, counter + strlen(counter) + 1), Return(0)));
    EXPECT_CALL(*g_fileIOMock, access(_, _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));

    getRebootReason(reason, sizeof(reason));
    EXPECT_STREQ(reason, "unknown");
}

TEST_F(StartParodusTestFixture, getRebootReason_StripsSpacesAndParentheses)
{
    char reason[128] = {'\0'};
    const char *counter = "1";
    const char *last_reboot_reason = "Software upgrade (manual)";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_LastRebootCounter"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(counter, counter + strlen(counter) + 1), Return(0)));
    EXPECT_CALL(*g_fileIOMock, access(_, _))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_LastRebootReason"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(last_reboot_reason,
                                            last_reboot_reason + strlen(last_reboot_reason) + 1),
                        Return(0)));

    getRebootReason(reason, sizeof(reason));
    EXPECT_STREQ(reason, "Softwareupgrademanual");
    getRebootReason(nullptr, sizeof(reason));
}

// getBootTime
TEST_F(StartParodusTestFixture, getBootTime_Success)
{
    unsigned int boot_time = 0;
    int wait_time = 0;

    getBootTime(&boot_time, &wait_time);
    EXPECT_GT(boot_time, 0u);
    EXPECT_EQ(wait_time, 0);

    getBootTime(nullptr, &wait_time);
    getBootTime(&boot_time, nullptr);
}

// getWebpaUrl / getAcquireJwt (webpa_cfg.json)
static void expectWebpaCfgJson(FILE *mockFile, const char *json_content, cJSON *root, cJSON *item)
{
    size_t json_size = strlen(json_content);

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, _))
        .Times(2)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .WillOnce(Return(json_size));
    EXPECT_CALL(*g_fileIOMock, fread(_, 1, json_size, mockFile))
        .WillOnce(Invoke([json_content, json_size](void *ptr, size_t size, size_t nmemb, FILE *stream) {
            memcpy(ptr, json_content, json_size);
            return json_size;
        }));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(item));
    EXPECT_CALL(*g_cjsonMock, cJSON_IsString(_))
        .WillOnce(Return(1));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);
}

TEST_F(StartParodusTestFixture, getWebpaUrl_NullAndProdBuild)
{
    EXPECT_EQ(nullptr, getWebpaUrl(nullptr));
    EXPECT_EQ(nullptr, getWebpaUrl("prod"));
}

TEST_F(StartParodusTestFixture, getWebpaUrl_DevBuild_FromConfig)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON mockJsonRoot = {};
    cJSON mockUrlItem = {};
    mockUrlItem.type = cJSON_String;
    mockUrlItem.valuestring = (char *)"https://dev.example.net:8080";

    expectWebpaCfgJson(mockFile, "{\"ServerIP\": \"https://dev.example.net:8080\"}",
                       &mockJsonRoot, &mockUrlItem);

    char *webpa_url = getWebpaUrl("dev");
    ASSERT_NE(webpa_url, nullptr);
    EXPECT_STREQ(webpa_url, "https://dev.example.net:8080");
    free(webpa_url);
}

TEST_F(StartParodusTestFixture, getWebpaUrl_DevBuild_ConfigMissing)
{
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_EQ(nullptr, getWebpaUrl("dev"));
}

TEST_F(StartParodusTestFixture, getAcquireJwt_FromConfig)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON mockJsonRoot = {};
    cJSON mockJwtItem = {};
    mockJwtItem.type = cJSON_String;
    mockJwtItem.valuestring = (char *)"0";

    expectWebpaCfgJson(mockFile, "{\"acquire-jwt\": \"0\"}", &mockJsonRoot, &mockJwtItem);

    EXPECT_EQ(0, getAcquireJwt());
}

TEST_F(StartParodusTestFixture, getAcquireJwt_EmptyConfig)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, _))
        .Times(2)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .WillOnce(Return(0));

    EXPECT_EQ(1, getAcquireJwt());
}

// getDeviceConfigFile
TEST_F(StartParodusTestFixture, getDeviceConfigFile_DevicePropsMissing)
{
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(nullptr));

    int ret = getDeviceConfigFile();
    EXPECT_TRUE(ret == -1 || (ret >= 1 && ret <= 3));
}

TEST_F(StartParodusTestFixture, getDeviceConfigFile_SECertSupported)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(1)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "UseSEBasedCert=true");
            return 1;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    int ret = getDeviceConfigFile();
    EXPECT_TRUE(ret == -1 || (ret >= 1 && ret <= 3));
}

// getWebpaConfig (PSM values)
TEST_F(StartParodusTestFixture, getWebpaConfig_FromPsm)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, mockFile))
        .Times(3)
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "0X=\"https://webpa.psm.net\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "1X=\"https://token.psm.net\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "2X=\"https://dns.psm.net\"\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    int ret = getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, &dns_text_url);
    EXPECT_EQ(0, ret);
    EXPECT_STREQ(webpa_url, "https://webpa.psm.net");
    EXPECT_STREQ(token_server_url, "https://token.psm.net");
    EXPECT_STREQ(dns_text_url, "https://dns.psm.net");

    free(webpa_url);
    free(token_server_url);
    free(dns_text_url);
}

// syncPsmDbOnUpgrade
TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SyncNotRequired)
{
    char firmware_version[] = "TestFirmware";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_LastRebootReason"), _, _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(3)
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(nullptr));

    syncPsmDbOnUpgrade(firmware_version);
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SyncOnSoftwareUpgrade)
{
    char firmware_version[] = "TestFirmware";
    const char *reboot_reason = "Software_upgrade";
    const char *cmc = "cmcValue";
    const char *cid = "cidValue";
    const char *sync_version = "syncVersion";
    FILE *psmGetFile = tmpfile();
    FILE *psmSetFile = tmpfile();
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(psmSetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_LastRebootReason"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(reboot_reason, reboot_reason + strlen(reboot_reason) + 1),
                        Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_COMCAST-COM_CMC"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(cmc, cmc + strlen(cmc) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_COMCAST-COM_CID"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(cid, cid + strlen(cid) + 1), Return(0)));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_COMCAST-COM_SyncProtocolVersion"), _, _))
        .Times(1)
        .WillOnce(DoAll(SetArrayArgument<2>(sync_version, sync_version + strlen(sync_version) + 1),
                        Return(0)));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillRepeatedly(Invoke(strcmp_s_real));

    // PSM health check, PSM get, PSM set, final PSM get.
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(4)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(psmSetFile))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmGetFile))
        .Times(3)
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "0X=\"0\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "1X=\"0\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "2X=\"0\"\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmSetFile))
        .Times(3)
        .WillRepeatedly(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "100\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(2)
        .WillRepeatedly(Return(0));

    syncPsmDbOnUpgrade(firmware_version);
}

// rdkb_log
TEST_F(StartParodusTestFixture, rdkb_log_LongMessage_Truncated)
{
    std::string long_state(2000, 'a');
    char *argv[] = {(char *)"parodusStart", (char *)"wan-status", &long_state[0], nullptr};

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(strcmp_s_real));

    EXPECT_EQ(1, handle_wan_status(3, argv));
}

// publishParodusCommand failures
TEST_F(StartParodusTestFixture, publishParodusCommand_fclose_Fail)
{
    EXPECT_CALL(*g_fileIOMock, fclose(_))
        .Times(1)
        .WillOnce(Invoke([](FILE *stream) {
            fflush(stream);
            close(fileno(stream));
            return -1;
        }));

    EXPECT_EQ(-1, publishParodusCommand("TestCommand"));
    remove("/tmp/parodusCmd.cmd");
}

TEST_F(StartParodusTestFixture, publishParodusCommand_open_Fail)
{
    remove("/tmp/parodusCmd.cmd");
    ASSERT_EQ(0, mkdir("/tmp/parodusCmd.cmd", 0755));

    EXPECT_EQ(-1, publishParodusCommand("TestCommand"));
    rmdir("/tmp/parodusCmd.cmd");
}

// buildParodusCommand append failures
TEST_F(StartParodusTestFixture, buildParodusCommand_AppendFailures)
{
    char full[2048] = {'\0'};
    char command[2048] = {'\0'};
    ParodusCommandConfig config = {};

    ASSERT_EQ(0, buildParodusCommand(full, sizeof(full), &config));
    size_t client_cert_pos = strstr(full, " --client-cert-path") - full;
    size_t crud_pos = strstr(full, " --crud-config-file") - full;
    size_t end_pos = strlen(full) - 2;

    EXPECT_EQ(-1, buildParodusCommand(command, client_cert_pos + 1, &config));
    EXPECT_EQ(-1, buildParodusCommand(command, crud_pos + 1, &config));
    EXPECT_EQ(-1, buildParodusCommand(command, end_pos + 1, &config));
}

// get_url
TEST_F(StartParodusTestFixture, get_url_UnknownEntry_seshat_url_strcpy_Fail)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
    char build_type[16] = {'\0'};
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "OTHER_KEY=value");
            return 1;
        }))
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SESHAT_URL=test_seshat_url");
            return 1;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(seshat_url, "");
}

// getDeviceMac
TEST_F(StartParodusTestFixture, getDeviceMac_EthWan_strcpy_Fail)
{
    char device_mac[32] = {'\0'};
    const char *eth_enabled = "true";
    const char *eth_mac = "aa:bb:cc:dd:ee:ff";

    EXPECT_CALL(*g_utopiaMock, s_sysevent_connect(_))
        .WillOnce(Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("eth_wan_enabled"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(eth_enabled, eth_enabled + strlen(eth_enabled) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("eth_wan_mac"), _, _))
        .WillOnce(DoAll(SetArrayArgument<3>(eth_mac, eth_mac + strlen(eth_mac) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getDeviceMac(device_mac, sizeof(device_mac)));
}

TEST_F(StartParodusTestFixture, getDeviceMac_DhcpInfo_RetryThenSuccess)
{
    char device_mac[32] = {'\0'};
    auto fillMac = [](PCMMGMT_CM_DHCP_INFO pInfo) {
        strcpy(pInfo->MACAddress, "00:11:22:33:44:55");
        return 0;
    };

    EXPECT_CALL(*g_utopiaMock, s_sysevent_connect(_))
        .WillOnce(Return(1));
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("eth_wan_enabled"), _, _))
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_cmHALMock, cm_hal_GetDHCPInfo(_))
        .Times(2)
        .WillOnce(Invoke(fillMac))
        .WillOnce(Invoke(fillMac));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(2)
        .WillOnce(Return(-1))
        .WillOnce(Invoke(strcpy_s_success));

    EXPECT_EQ(0, getDeviceMac(device_mac, sizeof(device_mac)));
    EXPECT_STREQ(device_mac, "00:11:22:33:44:55");
}

// getRebootReason strcpy failures
TEST_F(StartParodusTestFixture, getRebootReason_CounterZero_strcpy_Fail)
{
    char reason[128] = {'\0'};
    const char *counter = "0";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("X_RDKCENTRAL-COM_LastRebootCounter"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(counter, counter + strlen(counter) + 1), Return(0)));
    EXPECT_CALL(*g_fileIOMock, access(_, _))
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    getRebootReason(reason, sizeof(reason));
    EXPECT_STREQ(reason, "");
}

// getPartnerId
TEST_F(StartParodusTestFixture, getPartnerId_EmptyFromScript)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    FILE *output = tmpfile();
    ASSERT_NE(output, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(output));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, output))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_fileIOMock, pclose(output))
        .WillOnce(Return(0));

    EXPECT_EQ(0, getPartnerId(partner_id, sizeof(partner_id)));
    EXPECT_STREQ(partner_id, "");
}

TEST_F(StartParodusTestFixture, getPartnerId_strcmp_Fail)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    const char *configured_partner_id = "comcast";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(configured_partner_id,
                                            configured_partner_id + strlen(configured_partner_id) + 1),
                        Return(0)));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getPartnerId(partner_id, sizeof(partner_id)));
    EXPECT_STREQ(partner_id, "");
}

// getWebpaUrl - comcast server without port
TEST_F(StartParodusTestFixture, getWebpaUrl_DevComcast_WithPort)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON ip_item = {};
    cJSON port_item = {};
    ip_item.type = cJSON_String;
    ip_item.valuestring = (char *)"webpa.comcast.net";
    port_item.type = cJSON_String;
    port_item.valuestring = (char *)"8080";

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"ServerIP\": \"webpa.comcast.net\"}", 2);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(2)
        .WillRepeatedly(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&ip_item))
        .WillOnce(Return(&port_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(2);
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke(sprintf_s_success));

    char *webpa_url = getWebpaUrl("dev");
    ASSERT_NE(webpa_url, nullptr);
    EXPECT_STREQ(webpa_url, "https://webpa.comcast.net:8080");
    free(webpa_url);
}

TEST_F(StartParodusTestFixture, getWebpaUrl_DevComcast_PortMissing)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON ip_item = {};
    ip_item.type = cJSON_String;
    ip_item.valuestring = (char *)"webpa.comcast.net";

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"ServerIP\": \"webpa.comcast.net\"}", 2);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(2)
        .WillRepeatedly(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&ip_item))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(2);

    EXPECT_EQ(nullptr, getWebpaUrl("dev"));
}

TEST_F(StartParodusTestFixture, getWebpaUrl_DevComcast_sprintf_Fail)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON ip_item = {};
    cJSON port_item = {};
    ip_item.type = cJSON_String;
    ip_item.valuestring = (char *)"webpa.comcast.net";
    port_item.type = cJSON_String;
    port_item.valuestring = (char *)"8080";

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"ServerIP\": \"webpa.comcast.net\"}", 2);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(2)
        .WillRepeatedly(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&ip_item))
        .WillOnce(Return(&port_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(2);
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    char *webpa_url = getWebpaUrl("dev");
    ASSERT_NE(webpa_url, nullptr);
    EXPECT_STREQ(webpa_url, "webpa.comcast.net");
    free(webpa_url);
}

// getAcquireJwt - getValueFromCfgJson branches
TEST_F(StartParodusTestFixture, getAcquireJwt_NumberValue)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON jwt_item = {};
    jwt_item.type = cJSON_Number;
    jwt_item.valueint = 0;

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"acquire-jwt\": 0}", 1);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&jwt_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);

    EXPECT_EQ(0, getAcquireJwt());
}

TEST_F(StartParodusTestFixture, getAcquireJwt_UnsupportedType)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON jwt_item = {};
    jwt_item.type = cJSON_Array;

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"acquire-jwt\": []}", 1);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&jwt_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);

    EXPECT_EQ(1, getAcquireJwt());
}

TEST_F(StartParodusTestFixture, getAcquireJwt_ItemMissing)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{}", 1);
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);

    EXPECT_EQ(1, getAcquireJwt());
}

TEST_F(StartParodusTestFixture, getAcquireJwt_fread_Short)
{
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .WillOnce(Return(cfgFile));
    EXPECT_CALL(*g_fileIOMock, fseek(cfgFile, 0, _))
        .Times(2)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, ftell(cfgFile))
        .WillOnce(Return(10));
    EXPECT_CALL(*g_fileIOMock, fread(_, 1, 10, cfgFile))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(cfgFile))
        .WillOnce(Return(0));

    EXPECT_EQ(1, getAcquireJwt());
}

// getDeviceConfigFile - getSECertSupport branches
TEST_F(StartParodusTestFixture, getDeviceConfigFile_SECertNotInDeviceProps)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "OTHER_KEY=value");
            return 1;
        }))
        .WillOnce(Return(EOF));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .WillOnce(Return(0));

    int ret = getDeviceConfigFile();
    EXPECT_TRUE(ret == -1 || (ret >= 1 && ret <= 3));
}

TEST_F(StartParodusTestFixture, getDeviceConfigFile_SECert_strcpy_Fail)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "UseSEBasedCert=true");
            return 1;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .WillOnce(Return(0));

    int ret = getDeviceConfigFile();
    EXPECT_TRUE(ret == -1 || (ret >= 1 && ret <= 3));
}

// getDeviceConfigFile - certificate selection (creates the cert files when permitted)
static void expectSECertSupportTrue(FILE *mockFile)
{
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "UseSEBasedCert=true");
            return 1;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .WillOnce(Return(0));
}

TEST_F(StartParodusTestFixture, getDeviceConfigFile_SEDeviceCert)
{
    bool created = !fileExists(SE_DEVICE_CERT_PATH) && createFile(SE_DEVICE_CERT_PATH);
    if (!fileExists(SE_DEVICE_CERT_PATH)) {
        GTEST_SKIP() << "Cannot create " << SE_DEVICE_CERT_PATH;
    }
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    expectSECertSupportTrue(mockFile);

    EXPECT_EQ(1, getDeviceConfigFile());
    if (created) remove(SE_DEVICE_CERT_PATH);
}

TEST_F(StartParodusTestFixture, getDeviceConfigFile_DeviceCert)
{
    if (fileExists(SE_DEVICE_CERT_PATH)) {
        GTEST_SKIP() << SE_DEVICE_CERT_PATH << " already present";
    }
    bool created = !fileExists(DEVICE_CERT_PATH) && createFile(DEVICE_CERT_PATH);
    if (!fileExists(DEVICE_CERT_PATH)) {
        GTEST_SKIP() << "Cannot create " << DEVICE_CERT_PATH;
    }
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    expectSECertSupportTrue(mockFile);

    EXPECT_EQ(2, getDeviceConfigFile());
    if (created) remove(DEVICE_CERT_PATH);
}

TEST_F(StartParodusTestFixture, getDeviceConfigFile_StaticCert)
{
    if (fileExists(SE_DEVICE_CERT_PATH) || fileExists(DEVICE_CERT_PATH)) {
        GTEST_SKIP() << "Dynamic certificate already present";
    }
    bool created = !fileExists(STATIC_CERT_PATH) && createFile(STATIC_CERT_PATH);
    if (!fileExists(STATIC_CERT_PATH)) {
        GTEST_SKIP() << "Cannot create " << STATIC_CERT_PATH;
    }

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .WillOnce(Return(nullptr));

    EXPECT_EQ(3, getDeviceConfigFile());
    if (created) remove(STATIC_CERT_PATH);
}

// getWebpaConfig - partner JSON failures
TEST_F(StartParodusTestFixture, getWebpaConfig_PartnerFileMissing)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/partners_defaults.json"), StrEq("r")))
        .Times(3)
        .WillRepeatedly(Return(nullptr));

    EXPECT_EQ(-1, getWebpaConfig("prod", "*,comcast", &webpa_url, &token_server_url, &dns_text_url));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_Partner_strcpy_Fail)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Return(-1));

    EXPECT_EQ(-1, getWebpaConfig("prod", "comcast", &webpa_url, &token_server_url, &dns_text_url));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_PartnerFileEmpty)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *partnerFile = tmpfile();
    ASSERT_NE(partnerFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/partners_defaults.json"), StrEq("r")))
        .Times(3)
        .WillRepeatedly(Return(partnerFile));
    EXPECT_CALL(*g_fileIOMock, fseek(partnerFile, 0, _))
        .Times(6)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, ftell(partnerFile))
        .Times(3)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(partnerFile))
        .Times(3)
        .WillRepeatedly(Return(0));

    EXPECT_EQ(-1, getWebpaConfig("prod", "*,comcast", &webpa_url, &token_server_url, &dns_text_url));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_PartnerJsonInvalid)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *partnerFile = tmpfile();
    ASSERT_NE(partnerFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));
    expectCfgFileReads("/etc/partners_defaults.json", partnerFile, "{corrupt json", 3);
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(3)
        .WillRepeatedly(Return(nullptr));

    EXPECT_EQ(-1, getWebpaConfig("prod", "*,comcast", &webpa_url, &token_server_url, &dns_text_url));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_PartnerEmptyServerUrl_OnlyToken)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *partnerFile = tmpfile();
    ASSERT_NE(partnerFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON partner_obj = {};
    cJSON server_item = {};
    cJSON token_item = {};
    server_item.type = cJSON_String;
    server_item.valuestring = (char *)"";
    token_item.type = cJSON_String;
    token_item.valuestring = (char *)"https://token.comcast.net";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));
    expectCfgFileReads("/etc/partners_defaults.json", partnerFile, "{\"comcast\": {}}", 3);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(3)
        .WillRepeatedly(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&partner_obj))
        .WillOnce(Return(&server_item))
        .WillOnce(Return(&partner_obj))
        .WillOnce(Return(&token_item))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(3);

    EXPECT_EQ(-1, getWebpaConfig("prod", "*,comcast", &webpa_url, &token_server_url, &dns_text_url));
    EXPECT_EQ(webpa_url, nullptr);
    EXPECT_EQ(token_server_url, nullptr);
    EXPECT_EQ(dns_text_url, nullptr);
}

// getWebpaConfig - PSM parsing
TEST_F(StartParodusTestFixture, getWebpaConfig_Psm_sprintf_Fail)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, &dns_text_url));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_Psm_command_sprintf_Fail)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(4)
        .WillOnce(Invoke(sprintf_s_success))
        .WillOnce(Invoke(sprintf_s_success))
        .WillOnce(Invoke(sprintf_s_success))
        .WillOnce(Return(-1));

    EXPECT_EQ(-1, getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, &dns_text_url));
}

TEST_F(StartParodusTestFixture, getWebpaConfig_Psm_PartialValues)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *psmFile = tmpfile();
    ASSERT_NE(psmFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(psmFile));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmFile))
        .Times(3)
        .WillOnce(Return(nullptr))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "9X=\"unexpected\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "2X=\"https://dns.psm.net\"\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, pclose(psmFile))
        .WillOnce(Return(0));

    EXPECT_EQ(-1, getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, &dns_text_url));
    EXPECT_EQ(dns_text_url, nullptr);
}

TEST_F(StartParodusTestFixture, getWebpaConfig_Psm_EndOfFile)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *psmFile = tmpfile();
    ASSERT_NE(psmFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    fgetc(psmFile);

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(psmFile));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmFile))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "0X=\"https://webpa.psm.net\"\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, pclose(psmFile))
        .WillOnce(Return(0));

    EXPECT_EQ(0, getWebpaConfig("prod", nullptr, &webpa_url, &token_server_url, &dns_text_url));
    EXPECT_STREQ(webpa_url, "https://webpa.psm.net");
    free(webpa_url);
}

TEST_F(StartParodusTestFixture, getWebpaConfig_FromPsm_PartnerNotNeeded)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *psmFile = tmpfile();
    ASSERT_NE(psmFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(psmFile));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmFile))
        .Times(3)
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "0X=\"https://webpa.psm.net\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "1X=\"https://token.psm.net\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "2X=\"https://dns.psm.net\"\n", size);
            return buf;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, pclose(psmFile))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/partners_defaults.json"), _))
        .Times(0);

    EXPECT_EQ(0, getWebpaConfig("prod", "*,comcast", &webpa_url, &token_server_url, &dns_text_url));
    EXPECT_STREQ(webpa_url, "https://webpa.psm.net");

    free(webpa_url);
    free(token_server_url);
    free(dns_text_url);
}

// getWebpaConfig - dev build URL from webpa_cfg.json
TEST_F(StartParodusTestFixture, getWebpaConfig_DevBuildUrl)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *cfgFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON ip_item = {};
    ip_item.type = cJSON_String;
    ip_item.valuestring = (char *)"https://dev.example.net:8080";

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"ServerIP\": \"dev\"}", 1);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&ip_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(nullptr));

    EXPECT_EQ(0, getWebpaConfig("dev", nullptr, &webpa_url, &token_server_url, &dns_text_url));
    EXPECT_STREQ(webpa_url, "https://dev.example.net:8080");
    free(webpa_url);
}

TEST_F(StartParodusTestFixture, getWebpaConfig_DevBuildEmptyUrl_FallbackToPsm)
{
    char *webpa_url = nullptr;
    char *token_server_url = nullptr;
    char *dns_text_url = nullptr;
    FILE *cfgFile = tmpfile();
    FILE *psmFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(psmFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON ip_item = {};
    ip_item.type = cJSON_String;
    ip_item.valuestring = (char *)"";

    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"ServerIP\": \"\"}", 1);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(&root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(&ip_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(psmFile));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmFile))
        .Times(3)
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "0X=\"https://webpa.psm.net\"\n", size);
            return buf;
        }))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, pclose(psmFile))
        .WillOnce(Return(0));

    EXPECT_EQ(0, getWebpaConfig("dev", nullptr, &webpa_url, &token_server_url, &dns_text_url));
    EXPECT_STREQ(webpa_url, "https://webpa.psm.net");
    free(webpa_url);
}

// waitForPSMHealth
TEST_F(StartParodusTestFixture, waitForPSMHealth_fscanf_EOF)
{
    FILE *output = reinterpret_cast<FILE *>(1);

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .WillOnce(Return(output));
    EXPECT_CALL(*g_fileIOMock, fscanf(output, _, _))
        .WillOnce(Return(EOF));
    EXPECT_CALL(*g_fileIOMock, pclose(output))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(Invoke(strcmp_s_real));

    waitForPSMHealth("Test_Component");
}

// syncPsmDbOnUpgrade - webpa_cfg.json firmware handling
static void expectFirmwareConfig(FILE *cfgFile, cJSON *root, cJSON *fw_item, cJSON *new_item)
{
    expectCfgFileReads("/nvram/webpa_cfg.json", cfgFile, "{\"oldFirmwareVersion\": \"fw\"}", 1);
    expectJsonTypeChecks();
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .WillOnce(Return(root));
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .WillOnce(Return(fw_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_CreateString(_))
        .WillOnce(Return(new_item));
    EXPECT_CALL(*g_cjsonMock, cJSON_ReplaceItemInObject(_, _, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*g_cjsonMock, cJSON_Print(_))
        .WillOnce(Invoke([](const cJSON *json) { return strdup("{\"oldFirmwareVersion\": \"new\"}"); }));
    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1);
}

static void expectPsmGetValues(FILE *psmFile, const char *value)
{
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmFile))
        .Times(3)
        .WillOnce(Invoke([value](char *buf, int size, FILE *file) {
            snprintf(buf, size, "0X=\"%s\"\n", value);
            return buf;
        }))
        .WillOnce(Invoke([value](char *buf, int size, FILE *file) {
            snprintf(buf, size, "1X=\"%s\"\n", value);
            return buf;
        }))
        .WillOnce(Invoke([value](char *buf, int size, FILE *file) {
            snprintf(buf, size, "2X=\"%s\"\n", value);
            return buf;
        }));
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_FirmwareChanged_SyscfgValuesMissing)
{
    char firmware_version[] = "TestFirmware";
    FILE *cfgFile = tmpfile();
    FILE *writeFile = tmpfile();
    FILE *psmGetFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(writeFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON fw_item = {};
    cJSON new_item = {};
    fw_item.type = cJSON_String;
    fw_item.valuestring = (char *)"OldFirmware";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillRepeatedly(Invoke(strcmp_s_real));
    expectFirmwareConfig(cfgFile, &root, &fw_item, &new_item);
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("w")))
        .WillOnce(Return(writeFile));
    EXPECT_CALL(*g_fileIOMock, fclose(writeFile))
        .WillOnce(Return(0));
    // PSM health check, PSM get, final PSM get.
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(3)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(nullptr));
    expectPsmGetValues(psmGetFile, "0");
    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .WillRepeatedly(Return(0));

    syncPsmDbOnUpgrade(firmware_version);
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SameFirmware_ConfigWriteFail)
{
    char firmware_version[] = "OldFirmware";
    FILE *cfgFile = tmpfile();
    FILE *psmGetFile = tmpfile();
    ASSERT_NE(cfgFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    cJSON root = {};
    cJSON fw_item = {};
    cJSON new_item = {};
    fw_item.type = cJSON_String;
    fw_item.valuestring = (char *)"OldFirmware";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillRepeatedly(Invoke(strcmp_s_real));
    expectFirmwareConfig(cfgFile, &root, &fw_item, &new_item);
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("w")))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(3)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(nullptr));
    expectPsmGetValues(psmGetFile, "0");
    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .WillRepeatedly(Return(0));

    syncPsmDbOnUpgrade(firmware_version);
}

// syncPsmDbOnUpgrade - setValuesToPsmDb failures
static void expectSoftwareUpgradeSyscfg()
{
    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillRepeatedly(Invoke([](const char *ns, const char *name, char *out, int len) {
            snprintf(out, len, "%s",
                     strcmp(name, "X_RDKCENTRAL-COM_LastRebootReason") == 0 ? "Software_upgrade" : "value");
            return 0;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillRepeatedly(Invoke(strcmp_s_real));
    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/nvram/webpa_cfg.json"), StrEq("r")))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .WillRepeatedly(Return(0));
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SetValues_BadResponse)
{
    char firmware_version[] = "TestFirmware";
    FILE *psmGetFile = tmpfile();
    FILE *psmSetFile = tmpfile();
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(psmSetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    expectSoftwareUpgradeSyscfg();
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(4)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(psmSetFile))
        .WillOnce(Return(nullptr));
    expectPsmGetValues(psmGetFile, "0");
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmSetFile))
        .WillOnce(Return(nullptr));

    syncPsmDbOnUpgrade(firmware_version);
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SetValues_popen_Fail)
{
    char firmware_version[] = "TestFirmware";
    FILE *psmGetFile = tmpfile();
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    expectSoftwareUpgradeSyscfg();
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(4)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(nullptr));
    expectPsmGetValues(psmGetFile, "0");

    syncPsmDbOnUpgrade(firmware_version);
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SetValues_EndOfFile)
{
    char firmware_version[] = "TestFirmware";
    FILE *psmGetFile = tmpfile();
    FILE *psmSetFile = tmpfile();
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    ASSERT_NE(psmSetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    fgetc(psmSetFile);

    expectSoftwareUpgradeSyscfg();
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke(sprintf_s_success));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(4)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(psmSetFile))
        .WillOnce(Return(nullptr));
    expectPsmGetValues(psmGetFile, "0");
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, psmSetFile))
        .WillOnce(Invoke([](char *buf, int size, FILE *file) {
            strncpy(buf, "100\n", size);
            return buf;
        }));

    syncPsmDbOnUpgrade(firmware_version);
}

static void runSyncWithSprintfFailureAt(int fail_at)
{
    char firmware_version[] = "TestFirmware";
    FILE *psmGetFile = tmpfile();
    ASSERT_NE(psmGetFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    int calls = 0;

    expectSoftwareUpgradeSyscfg();
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Invoke([&calls, fail_at](char *dest, size_t dmax, size_t n, const char *formatted) {
            return ++calls == fail_at ? -1 : sprintf_s_success(dest, dmax, n, formatted);
        }));
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(3)
        .WillOnce(Return(nullptr))
        .WillOnce(Return(psmGetFile))
        .WillOnce(Return(nullptr));
    expectPsmGetValues(psmGetFile, "0");

    syncPsmDbOnUpgrade(firmware_version);
}

// sprintf_s calls: 1-2 PSM health, 3-6 PSM get, 7-9 PSM set values, 10 PSM set command.
TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SetValues_tempBuf_sprintf_Fail)
{
    runSyncWithSprintfFailureAt(7);
}

TEST_F(StartParodusTestFixture, syncPsmDbOnUpgrade_SetValues_command_sprintf_Fail)
{
    runSyncWithSprintfFailureAt(10);
}

// log_init / log_close (kept last: a successful log_init redirects stderr)
TEST_F(StartParodusTestFixture, log_init_strcpy_Fail)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(1)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_START_LOG_FILE=/tmp/parodusStart_ut.log");
            return 1;
        }));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(nullptr, log_init());
}

TEST_F(StartParodusTestFixture, log_init_Success_And_log_close)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .Times(1)
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_START_LOG_FILE=/tmp/parodusStart_ut.log");
            return 1;
        }))
        .WillOnce(Return(EOF));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, fclose(_))
        .Times(2)
        .WillRepeatedly(Return(0));

    EXPECT_NE(nullptr, log_init());
    log_close();
}

// Must stay last: a failed freopen closes stderr for the rest of the run.
TEST_F(StartParodusTestFixture, log_init_freopen_Fail)
{
    FILE *mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(StrEq("/etc/device.properties"), StrEq("r")))
        .WillOnce(Return(mockFile));
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_START_LOG_FILE=/nonexistent_dir/parodusStart.log");
            return 1;
        }))
        .WillOnce(Return(EOF));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke(strcpy_s_success));
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .WillOnce(Return(0));

    EXPECT_EQ(nullptr, log_init());
}

