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
#include "safec_lib_common.h"
#include "cJSON.h"
void getPartnerId(char *partner_id);
int addParodusCmdToFile(char *command);
int  writeToJson(char *data);
void getWebpaValuesFromPsmDb(char *names[], char **values,int count);
void getValuesFromPsmDb(char *names[], char **values,int count);
void getValuesFromSysCfgDb(char *names[], char **values,int count);
void get_parodusStart_logFile(char *parodusStart_Log);
int checkServerUrlFormat(char *serverUrl);
void checkAndUpdateServerUrlFromDevCfg(char **serverUrl);
void getValueFromCfgJson( char *key, char **value, cJSON **out);
int setValuesToPsmDb(char *names[], char **values,int count);
void get_url(char *parodus_url, char *seshat_url, char *build_type);
void free_sync_db_items(int paramCount,char *psmValues[],char *sysCfgValues[]);
void waitForPSMHealth(char *compName);
void getSECertSupport(char *seCert_support);
int syncXpcParamsOnUpgrade(char *lastRebootReason, char *firmwareVersion);
}

#define MAX_PARTNERID_LEN              64
int numLoops;

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
    }
};

// getPartnerId
TEST_F(StartParodusTestFixture, getPartnerId_PartnerIdExists)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    const char* expected_partner_id = "TEST_PARTNER_ID";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(
            ::testing::SetArgPointee<2>(*expected_partner_id),
            ::testing::SetArrayArgument<2>(expected_partner_id, expected_partner_id + strlen(expected_partner_id) + 1),
            Return(0)
        ));

    getPartnerId(partner_id);
    EXPECT_STREQ(partner_id, expected_partner_id);
}

TEST_F(StartParodusTestFixture, getPartnerId_new_partnerID_Successful_get)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(
            ::testing::WithArg<2>(::testing::Invoke([](char* arg) { arg[0] = '\0'; })),
            Return(0)
        ));
    
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, mockFile))
        .Times(1)
        .WillOnce(DoAll(
            ::testing::WithArg<0>(::testing::Invoke([](char* buf) {
                strcpy(buf, "TEST_PARTNER_ID\n");
            })),
            Return(reinterpret_cast<char*>(1))
        ));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    getPartnerId(partner_id);
    EXPECT_STREQ(partner_id, "TEST_PARTNER_ID");
}

TEST_F(StartParodusTestFixture, getPartnerId_popen_Fail)
{
    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .Times(1)
        .WillOnce(Return(1));
    
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));
    
    getPartnerId(partner_id);
    EXPECT_STREQ(partner_id, "");
}


TEST_F(StartParodusTestFixture, getPartnerId_fgets_error)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    char partner_id[MAX_PARTNERID_LEN] = {'\0'};
    EXPECT_CALL(*g_syscfgMock, syscfg_get(nullptr, StrEq("PartnerID"), _, _))
        .WillOnce(DoAll(
            ::testing::WithArg<2>(::testing::Invoke([](char* arg) { arg[0] = '\0'; })),
            Return(0)
        ));
    
    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, mockFile))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    getPartnerId(partner_id);
    EXPECT_STREQ(partner_id, "");
}

// addParodusCmdToFile
TEST_F(StartParodusTestFixture, addParodusCmdToFile_Success) {
    char expected_command[] = "TestCommand";
    char buffer[100] = {0};

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, ferror(_))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    int ret = addParodusCmdToFile(expected_command);
    EXPECT_EQ(0, ret);
    remove("/tmp/parodusCmd.cmd");
}

TEST_F(StartParodusTestFixture, addParodusCmdToFile_Failure) {
    char expected_command[] = "TestCommand";
    char buffer[100] = {0};

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    int ret = addParodusCmdToFile(expected_command);
    EXPECT_EQ(-1, ret);
}

TEST_F(StartParodusTestFixture, addParodusCmdToFile_Ferror) {
    char expected_command[] = "TestCommand";
    char buffer[100] = {0};

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, ferror(_))
        .Times(1)
        .WillOnce(Return(1));
    
    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    int ret = addParodusCmdToFile(expected_command);

    EXPECT_EQ(-1, ret);
}

// writeToJson
TEST_F(StartParodusTestFixture, writeToJson_Success) {
    char testData[] = "Test Data";
    char buffer[100];

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    int ret = writeToJson(testData);
    EXPECT_EQ(0, ret);
}

TEST_F(StartParodusTestFixture, writeToJson_Failure) {
    char testData[] = "Test Data";
    char buffer[100];

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));
    
    int ret = writeToJson(testData);

    EXPECT_EQ(-1, ret);
}

// GetValuesFromSysCfgDb
TEST_F(StartParodusTestFixture, GetValuesFromSysCfgDb_Success)
{
    const char* names[] = {"param1", "param2"};
    char* values[2] = {nullptr};
    int count = 2;

    const char* expected_value1 = "value1";
    const char* expected_value2 = "value2";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("param1"), _, _))
        .WillOnce(DoAll(
            SetArrayArgument<2>(expected_value1, expected_value1 + strlen(expected_value1) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("param2"), _, _))
        .WillOnce(DoAll(
            SetArrayArgument<2>(expected_value2, expected_value2 + strlen(expected_value2) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    getValuesFromSysCfgDb(const_cast<char**>(names), values, count);

    ASSERT_NE(values[0], nullptr);
    ASSERT_NE(values[1], nullptr);
    EXPECT_STREQ(values[0], "value1");
    EXPECT_STREQ(values[1], "value2");

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, GetValuesFromSysCfgDb_SyscfgGet_Failure)
{
    const char* names[] = {"param1", "param2"};
    char* values[2] = {nullptr};
    int count = 2;

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("param1"), _, _))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("param2"), _, _))
        .WillOnce(Return(-1));

    getValuesFromSysCfgDb(const_cast<char**>(names), values, count);
    EXPECT_EQ(values[0], nullptr);
    EXPECT_EQ(values[1], nullptr);
}

TEST_F(StartParodusTestFixture, GetValuesFromSysCfgDb_Strcpy_Failure)
{
    const char* names[] = {"param1", "param2"};
    char* values[2] = {nullptr};
    int count = 2;

    const char* expected_value1 = "value1";

    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, StrEq("param1"), _, _))
        .WillOnce(DoAll(
            SetArrayArgument<2>(expected_value1, expected_value1 + strlen(expected_value1) + 1),
            Return(0)
        ));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            return -1;
        }));

    getValuesFromSysCfgDb(const_cast<char**>(names), values, count);
    ASSERT_NE(values[0], nullptr);
    EXPECT_STRNE(values[0], expected_value1);

    for (int i = 0; i < count; ++i)
    {
        if (values[i]) {
            free(values[i]);
        }
    }
}

// getWebpaValuesFromPsmDb
TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_Single_Parameter)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[1] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " 0X %s", "eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e 0X eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "0X=\"value1\"\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);
    EXPECT_NE(values[0], nullptr);
    if (values[0]) EXPECT_STREQ(values[0], "value1");

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_Parameter_Fail)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[1] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);
    EXPECT_EQ(values[0], nullptr);

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_popen_Fail)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[1] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);
    EXPECT_EQ(values[0], nullptr);

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_Command_Fail)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[1] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(0))
        .WillOnce(Return(-1));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);
    EXPECT_EQ(values[0], nullptr);

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_fgets_Fail)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[1] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " 0X %s", "eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e 0X eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);
    EXPECT_EQ(values[0], nullptr);

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}


TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_strcpy_Fail)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[1] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " 0X %s", "eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e 0X eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "0X=\"value1\"\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);
    if (values[0]) EXPECT_STRNE(values[0], "value1");

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, getWebpaValuesFromPsmDb_multiple_parameters)
{
    const char* names[] = {
        "eRT.com.cisco.spvtg.ccsp.webpa.param1",
        "eRT.com.cisco.spvtg.ccsp.webpa.param2"
    };
    char* values[2] = {nullptr};
    int count = 2;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " 0X %s", "eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " 1X %s", "eRT.com.cisco.spvtg.ccsp.webpa.param2");
            return strlen(buf);
        }))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e '0X=\"eRT.com.cisco.spvtg.ccsp.webpa.param1\" 1X=\"eRT.com.cisco.spvtg.ccsp.webpa.param2\"'");
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(::testing::AnyNumber())
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "0X=\"value1\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "1X=\"value2\"\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    getWebpaValuesFromPsmDb(const_cast<char**>(names), values, count);

    printf("[DEBUG_T] PRINTING VALUES DATA\n");
    for (int i = 0; i < count; i++) {
        printf("[DEBUG_T] value[%d] = %s\n", i, values[i]);
    }

    EXPECT_NE(values[0], nullptr);
    EXPECT_NE(values[1], nullptr);
    if (values[0]) EXPECT_STREQ(values[0], "value1");
    if (values[1]) EXPECT_STREQ(values[1], "value2");

    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

// getValuesFromPsmDb
TEST_F(StartParodusTestFixture, getValuesFromPsmDb_one_parameter)
{
    const char* names[] = {"eRT.com.cisco.spvtg.ccsp.webpa.param1"};
    char* values[] = {nullptr};
    int count = 1;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " 0X eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e 0X eRT.com.cisco.spvtg.ccsp.webpa.param1");
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "0X=\"value1\"\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    getValuesFromPsmDb(const_cast<char**>(names), values, count);

    printf("[DEBUG_T] PRINTING VALUES DATA\n");
    for(int i=0; i<count; i++) {
        printf("[DEBUG_T] value[%d] = %s\n", i, values[i]);
    }

    EXPECT_NE(values[0], nullptr);
    if (values[0]) EXPECT_STREQ(values[0], "value1");

    for (int i = 0; i < count; ++i) {
        if(values[i]) {
            free(values[i]);
        }
    }
}

TEST_F(StartParodusTestFixture, getValuesFromPsmDb_multiple_parameter)
{
    const char* names[] = {
        "eRT.com.cisco.spvtg.ccsp.webpa.param1",
        "eRT.com.cisco.spvtg.ccsp.webpa.param2"
    };
    char* values[2] = {nullptr};
    int count = 2;
    char pathPrefix[]  = "eRT.com.cisco.spvtg.ccsp.webpa.";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s %s", pathPrefix, "param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s %s", pathPrefix, "param2");
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e '%s=\"param1\" %s=\"param2\"'", pathPrefix, pathPrefix);
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(::testing::AnyNumber())
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "0X=\"value1\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "1X=\"value2\"\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));
    
    getValuesFromPsmDb(const_cast<char**>(names), values, count);

    printf("[DEBUG_T] PRINTING VALUES DATA\n");
    for (int i = 0; i < count; i++) {
        printf("[DEBUG_T] value[%d] = %s\n", i, values[i]);
    }

    // Verify that both values were correctly set
    EXPECT_NE(values[0], nullptr);
    EXPECT_NE(values[1], nullptr);
    if (values[0]) EXPECT_STREQ(values[0], "value1");
    if (values[1]) EXPECT_STREQ(values[1], "value2");

    // Clean up allocated memory
    for (int i = 0; i < count; ++i) {
        if (values[i]) {
            free(values[i]);
        }
    }
}

// SetValuesToPsmDb
TEST_F(StartParodusTestFixture, SetValuesToPsmDb_one_parameter)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1")};
    char* values[] = {const_cast<char*>("value1")};
    int count = 1;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli set %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "100\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, 0);
}

TEST_F(StartParodusTestFixture, SetValuesToPsmDb_multiple_parameters)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1"), const_cast<char*>("param2")};
    char* values[] = {const_cast<char*>("value1"), const_cast<char*>("value2")};
    int count = 2;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(3)
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[1], values[1]);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli set %s%s %s %s%s %s", pathPrefix, names[0], values[0], pathPrefix, names[1], values[1]);  // Command prefix or extra formatting
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "100\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, 0);
}

TEST_F(StartParodusTestFixture, SetValuesToPsmDb_tempBuf_Failed)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1")};
    char* values[] = {const_cast<char*>("value1")};
    int count = 1;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, -1);
}


TEST_F(StartParodusTestFixture, SetValuesToPsmDb_command_error)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1")};
    char* values[] = {const_cast<char*>("value1")};
    int count = 1;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli set %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, -1);
}

TEST_F(StartParodusTestFixture, SetValuesToPsmDb_fgets_error)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1")};
    char* values[] = {const_cast<char*>("value1")};
    int count = 1;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli set %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, -1);
}

TEST_F(StartParodusTestFixture, SetValuesToPsmDb_command_snprintf_error)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1")};
    char* values[] = {const_cast<char*>("value1")};
    int count = 1;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(2)
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }))
        .WillOnce(Return(-1));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, -1);
}

TEST_F(StartParodusTestFixture, SetValuesToPsmDb_Bad_Response)
{
    const char* pathPrefix = "eRT.com.cisco.spvtg.ccsp.webpa.";
    char* names[] = {const_cast<char*>("param1")};
    char* values[] = {const_cast<char*>("value1")};
    int count = 1;
    int retVal = 0;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &names, &values](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli set %s%s %s", pathPrefix, names[0], values[0]);
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "400\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    retVal = setValuesToPsmDb(names, values, count);
    EXPECT_EQ(retVal, -1);
}

// free_sync_db_items
TEST_F(StartParodusTestFixture, free_sync_db_items_Success)
{
    int paramCount = 3;
    char** psmValues = new char*[paramCount];
    char** sysCfgValues = new char*[paramCount];

    // Populate the array
    for (int i = 0; i < paramCount; i++) {
        psmValues[i] = (char*)malloc(20);
        snprintf(psmValues[i], 20, "psmValue%d", i);

        sysCfgValues[i] = (char*)malloc(25);
        snprintf(sysCfgValues[i], 25, "sysCfgValue%d", i);
    }

    free_sync_db_items(paramCount, psmValues, sysCfgValues);

    for (int i = 0; i < paramCount; i++) {
        EXPECT_EQ(psmValues[i], nullptr);
        EXPECT_EQ(sysCfgValues[i], nullptr);
    }
}

TEST_F(StartParodusTestFixture, checkServerUrlFormat_ValidUrl)
{
    char validUrl1[] = "http://example.com:8080";
    int ret = checkServerUrlFormat(validUrl1);
    EXPECT_EQ(ret, 1);
}

TEST_F(StartParodusTestFixture, checkServerUrlFormat_InvalidUrl)
{
    char validUrl1[] = "http://invalid.example.com";
    int ret = checkServerUrlFormat(validUrl1);
    EXPECT_EQ(ret, 0);
}

// getValueFromCfgJson
TEST_F(StartParodusTestFixture, getValueFromCfgJson_fopen_Fail)
{
    char *testKey = (char *)"someKey";
    char *expectedValue = (char *)"someValue";
    char *value = nullptr;
    cJSON *mockJson = nullptr;

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    getValueFromCfgJson(testKey, &value, &mockJson);
    EXPECT_EQ(value, nullptr);
}


TEST_F(StartParodusTestFixture, getValueFromCfgJson_Ftell_Fail)
{
    char *testKey = (char *)"someKey";
    char *expectedValue = (char *)"someValue";
    char *value = nullptr;
    cJSON *mockJson = nullptr;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(_, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(_))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(_))
        .Times(1)
        .WillOnce(Return(0));

    getValueFromCfgJson(testKey, &value, &mockJson);
    EXPECT_EQ(value, nullptr);
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_Empty_Data_Fail)
{
    char *testKey = (char *)"someKey";
    char *expectedValue = (char *)"someValue";
    char *value = nullptr;
    cJSON *mockJson = nullptr;

    const char* mockJsonContent = "{\"MaxPingWaitTimeInSec\n\": 10}";
    size_t mockJsonSize = strlen(mockJsonContent);

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";


    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, _, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getValueFromCfgJson(testKey, &value, &mockJson);
    EXPECT_EQ(value, nullptr);
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_First_jsonParse_Error_RecoverySuccess)
{
    char *testKey = (char *)"someKey";
    char *value = nullptr;
    cJSON *mockJson = nullptr;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    const char* mockJsonContent = "{\"MaxPingWaitTimeInSec\n\": 10}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(2)
        .WillOnce(::testing::Return(nullptr))
        .WillOnce(::testing::Return(nullptr));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetErrorPtr())
        .Times(1)
        .WillOnce(Return("Error at character 5"));

    getValueFromCfgJson(testKey, &value, &mockJson);
    EXPECT_EQ(value, nullptr);
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_First_jsonParse_Error_RecoveryFailed) {
    char *testKey = (char *)"someKey";
    char *value = nullptr;
    cJSON *mockJson = nullptr;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    const char* mockJsonContent = "{\"MaxPingWaitTimeInSec\n\": 10}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(2)
        .WillOnce(Return(mockFile))
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));

    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(2)
        .WillOnce(::testing::Return(nullptr)) 
        .WillOnce(Invoke([](const char* str) { 
            cJSON* mock_json = new cJSON();
            return mock_json;
        }));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetErrorPtr())
        .Times(1)
        .WillOnce(Return("Error at character 5"));

    const char* mockJsonPrintOutput = "{\"MaxPingWaitTimeInSec\": 10}";
    EXPECT_CALL(*g_cjsonMock, cJSON_Print(_))
        .Times(1)
        .WillOnce(Return(strdup(mockJsonPrintOutput)));

    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1)
        .WillOnce(Invoke([](cJSON* json) { delete json; }));

    getValueFromCfgJson(testKey, &value, &mockJson);
    EXPECT_EQ(value, nullptr);
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_First_jsonParse_Success_String)
{
    char *testKey = (char *)"someOtherKey";
    char *value = nullptr;
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_String;
    mockJson->valuestring = strdup("someValue");

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"someOtherKey\": \"someValue\"}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockJson));

    getValueFromCfgJson(testKey, &value, &mockJson);

    ASSERT_NE(value, nullptr);
    EXPECT_STREQ(value, "someValue");

    free(value);
    delete mockJson;
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_First_jsonParse_Success_Number) {
    char *testKey = (char *)"someOtherKey";
    char *value = nullptr;
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_Number;
    mockJson->valueint = 123;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"someOtherKey\": \"someValue\"}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockJson));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([mockJson](char *buf, size_t size, size_t n, const char *format) {
            snprintf(buf, size, format, mockJson->valueint);
            return strlen(buf);
        }));

    getValueFromCfgJson(testKey, &value, &mockJson);
    ASSERT_NE(value, nullptr);
    EXPECT_STREQ(value, "123");

    free(value);
    delete mockJson;
}


TEST_F(StartParodusTestFixture, getValueFromCfgJson_First_jsonParse_Success_sprintf_error) {
    char *testKey = (char *)"someOtherKey";
    char *value = nullptr;
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_Number;
    mockJson->valueint = 123;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"someOtherKey\": \"someValue\"}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockJson));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    getValueFromCfgJson(testKey, &value, &mockJson);

    ASSERT_NE(value, "123") << "value is somehow got written. But it shouldnt be." <<endl;

    free(value);
    delete mockJson;
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_First_jsonParse_Invalid_cJSON_type) {
    char *testKey = (char *)"someOtherKey";
    char *value = nullptr;
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_NULL;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"someOtherKey\": []}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(1)
        .WillRepeatedly(Return(mockJson));

    getValueFromCfgJson(testKey, &value, &mockJson);

    ASSERT_EQ(value, nullptr) << "value is somehow got written. But it shouldnt be." <<endl;

    free(value);
    delete mockJson;
}

TEST_F(StartParodusTestFixture, getValueFromCfgJson_cJSON_GetObjectItem_Fail) {
    char *testKey = (char *)"someOtherKey";
    char *value = nullptr;
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_NULL;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"someOtherKey\": []}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    getValueFromCfgJson(testKey, &value, &mockJson);

    ASSERT_EQ(value, nullptr) << "value is somehow got written. But it shouldnt be." <<endl;

    free(value);
    delete mockJson;
}


// Test cases for checkAndUpdateServerUrlFromDevCfg
TEST_F(StartParodusTestFixture, checkAndUpdateServerUrlFromDevCfg_InvalidUrl_ValidPort) {
    char* serverUrl = nullptr;
    checkAndUpdateServerUrlFromDevCfg(&serverUrl);
    ASSERT_STREQ(serverUrl, nullptr);
    free(serverUrl);
}

TEST_F(StartParodusTestFixture, checkAndUpdateServerUrlFromDevCfg_ValidURL) {
    char* serverUrl = strdup("https://valid.url.comcast.com:8080");
    char* expectedUpdatedUrl = strdup(serverUrl);

    checkAndUpdateServerUrlFromDevCfg(&serverUrl);
    ASSERT_STREQ(serverUrl, expectedUpdatedUrl);

    free(serverUrl);
    free(expectedUpdatedUrl);
}

TEST_F(StartParodusTestFixture, checkAndUpdateServerUrlFromDevCfg_InvalidURL_WebCfg_File_Failure) {
    char* serverUrl = strdup("invalid.url.comcast.com");
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    checkAndUpdateServerUrlFromDevCfg(&serverUrl);

    ASSERT_STREQ(serverUrl, nullptr);
    free(serverUrl);
}

TEST_F(StartParodusTestFixture, checkAndUpdateServerUrlFromDevCfg_Success)
{
    char *serverUrl = strdup("invalidcomcast.com");
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_String;
    mockJson->valuestring = strdup("8080");

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"ServerPort\": \"8080\"}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockJson));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char *buf, size_t maxlen, int flag, const char *format) {
            snprintf(buf, maxlen, format, "8080");
            return strlen(buf);
        }));

    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
    .Times(1)
    .WillOnce(Invoke([](cJSON* json) {
        if (json && json->valuestring) {
            free(json->valuestring);
        }
        delete json;
    }));

    checkAndUpdateServerUrlFromDevCfg(&serverUrl);

    ASSERT_NE(serverUrl, nullptr);
    EXPECT_STREQ(serverUrl, "https://invalidcomcast.com:8080");

    free(serverUrl);
}


TEST_F(StartParodusTestFixture, checkAndUpdateServerUrlFromDevCfg_sprintf_error)
{
    char *serverUrl = strdup("invalidcomcast.com");
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_String;
    mockJson->valuestring = strdup("8080");

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"ServerPort\": \"8080\"}";
    size_t mockJsonSize = strlen(mockJsonContent);

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, StrEq("r+")))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockJson));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
    .Times(1)
    .WillOnce(Invoke([](cJSON* json) {
        if (json && json->valuestring) {
            free(json->valuestring);
        }
        delete json;
    }));

    checkAndUpdateServerUrlFromDevCfg(&serverUrl);
    ASSERT_STRNE(serverUrl,  "https://invalidcomcast.com:8080");
    free(serverUrl);
}

// waitForPSMHealth
TEST_F(StartParodusTestFixture, waitForPSMHealth_Fail)
{
    char component_name[] = "Test_Component";
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    waitForPSMHealth(component_name);
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_SPRINTF_Fail)
{
    char component_name[] = "Test_Component";
    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .WillOnce(Return(0))
        .WillOnce(Return(-1));

    waitForPSMHealth(component_name);
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_Green_First)
{
    char component_name[] = "Test_Component";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(2)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(_, _, _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    waitForPSMHealth(component_name);
}


TEST_F(StartParodusTestFixture, waitForPSMHealth_Popen_Fail)
{
    char component_name[] = "Test_Component";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(2)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(1)
        .WillOnce(Return(nullptr));

    waitForPSMHealth(component_name);
}


TEST_F(StartParodusTestFixture, waitForPSMHealth_Green_After_a_Retry)
{
    char component_name[] = "Test_Component";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    numLoops = 2;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(_, _, _))
        .Times(2)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(2)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(-1), Return(-1)))
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));

    waitForPSMHealth(component_name);
}

TEST_F(StartParodusTestFixture, waitForPSMHealth_Never_Green)
{
    char component_name[] = "Test_Component";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    numLoops = 7;

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(numLoops+1)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(numLoops)
        .WillRepeatedly(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(_, _, _))
        .Times(numLoops)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(numLoops)
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .Times(numLoops)
        .WillRepeatedly(DoAll(SetArgPointee<3>(0), Return(-1)));

    waitForPSMHealth(component_name);
}

// getSECertSupport
TEST_F(StartParodusTestFixture, getSECertSupport_DEVICE_PROPS_FILE_Fail)
{
    char seCert_support[1024] = {'\0'};
    // Mock fopen Failure for DEVICE_PROPS_FILE
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _)).WillOnce(Return(nullptr));

    // If fopen Fails, seCert_support is not feteched from DEVICE_PROPS_FILE
    getSECertSupport(seCert_support);
    ASSERT_STREQ(seCert_support, "");
}

TEST_F(StartParodusTestFixture, getSECertSupport_GET_SUCCESS)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    
    char seCert_support[1024] = {'\0'};
    const char* expected_value = "testData";
    // Successful fopen
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _)).WillOnce(Return(mockFile));

    // Simulating successful file read
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "UseSEBasedCert=%s", expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getSECertSupport(seCert_support);
    ASSERT_STREQ(seCert_support, expected_value);
}

TEST_F(StartParodusTestFixture, getSECertSupport_STR_ERROR_Fail)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    
    char seCert_support[1024] = {'\0'};
    const char* expected_value = "testData";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _)).WillOnce(Return(mockFile));

    // Mock successful file read
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(1)
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "UseSEBasedCert=%s", expected_value);
            return 1;
        }));
    // strcpy_s Failure
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getSECertSupport(seCert_support);
    ASSERT_STREQ(seCert_support, "");
}

TEST_F(StartParodusTestFixture, getSECertSupport_GET_SUCCESS_RETRY)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    
    char seCert_support[1024] = {'\0'};
    const char* expected_value = "testData";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    // Mock successful file read on second attempt
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(3)
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SomeOtherCert=%s", "otherData");
            return 1;
        }))
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "UseSEBasedCert=%s", expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    getSECertSupport(seCert_support);
    ASSERT_STREQ(seCert_support, expected_value);
}

// Test cases for get_parodusStart_logFile
TEST_F(StartParodusTestFixture, get_parodusStart_logFile_DEVICE_PROPS_FILE_Fail)
{
    char parodusStart_Log[1024] = {'\0'};
    // Mock fopen Failure for DEVICE_PROPS_FILE
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _)).WillOnce(Return(nullptr));

    // If fopen Fails, parodusStart_Log is not feteched from DEVICE_PROPS_FILE
    get_parodusStart_logFile(parodusStart_Log);
    ASSERT_STREQ(parodusStart_Log, "");
}

TEST_F(StartParodusTestFixture, get_parodusStart_logFile_GET_SUCCESS)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    
    char parodusStart_Log[1024] = {'\0'};
    const char* expected_value = "testData";
    // Successful fopen
    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _)).WillOnce(Return(mockFile));

    // Simulating successful file read
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_START_LOG_FILE=%s", expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    get_parodusStart_logFile(parodusStart_Log);
    ASSERT_STREQ(parodusStart_Log, expected_value);
}

TEST_F(StartParodusTestFixture, get_parodusStart_logFile_STR_ERROR_Fail)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    
    char parodusStart_Log[1024] = {'\0'};
    const char* expected_value = "testData";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _)).WillOnce(Return(mockFile));

    // Mock successful file read
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(1)
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_START_LOG_FILE=%s", expected_value);
            return 1;
        }));
    // strcpy_s Failure
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    get_parodusStart_logFile(parodusStart_Log);
    ASSERT_STREQ(parodusStart_Log, "");
}

TEST_F(StartParodusTestFixture, get_parodusStart_logFile_GET_SUCCESS_RETRY)
{
    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";
    
    char parodusStart_Log[1024] = {'\0'};
    const char* expected_value = "testData";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    // Mock successful file read on second attempt
    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(3)
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SomeOtherCert=%s", "otherData");
            return 1;
        }))
        .WillOnce(Invoke([expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_START_LOG_FILE=%s", expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));

    get_parodusStart_logFile(parodusStart_Log);
    ASSERT_STREQ(parodusStart_Log, expected_value);
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

TEST_F(StartParodusTestFixture, get_url_only_parodus_url)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "test_parodus_url";
    const char* seshat_url_expected_value = "";
    const char* build_type_expected_value = "" ;


    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([parodus_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=%s", parodus_url_expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, parodus_url_expected_value);
    EXPECT_STREQ(seshat_url, seshat_url_expected_value);
    EXPECT_STREQ(build_type, build_type_expected_value);  
}

TEST_F(StartParodusTestFixture, get_url_only_seshat_url)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "";
    const char* seshat_url_expected_value = "test_seshat_url";
    const char* build_type_expected_value = "" ;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([seshat_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SESHAT_URL=%s", seshat_url_expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, parodus_url_expected_value);
    EXPECT_STREQ(seshat_url, seshat_url_expected_value);
    EXPECT_STREQ(build_type, build_type_expected_value);  
}


TEST_F(StartParodusTestFixture, get_url_only_build_type)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "";
    const char* seshat_url_expected_value = "";
    const char* build_type_expected_value = "test_build_type" ;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([build_type_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "BUILD_TYPE=%s", build_type_expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, parodus_url_expected_value);
    EXPECT_STREQ(seshat_url, seshat_url_expected_value);
    EXPECT_STREQ(build_type, build_type_expected_value);  
}

TEST_F(StartParodusTestFixture, get_url_GET_ALL)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "test_parodus_url";
    const char* seshat_url_expected_value = "test_seshat_url";
    const char* build_type_expected_value = "test_build_type" ;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(4)
        .WillOnce(Invoke([parodus_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=%s", parodus_url_expected_value);
            return 1;
        }))
        .WillOnce(Invoke([seshat_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SESHAT_URL=%s", seshat_url_expected_value);
            return 1;
        }))
        .WillOnce(Invoke([build_type_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "BUILD_TYPE=%s", build_type_expected_value);
            return 1;
        }))
        .WillOnce(Return(EOF));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillRepeatedly(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, parodus_url_expected_value);
    EXPECT_STREQ(seshat_url, seshat_url_expected_value);
    EXPECT_STREQ(build_type, build_type_expected_value);  
}

TEST_F(StartParodusTestFixture, get_url_parodus_url_strcpy_Fail)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "test_parodus_url";
    const char* seshat_url_expected_value = "test_seshat_url";
    const char* build_type_expected_value = "test_build_type" ;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(1)
        .WillOnce(Invoke([parodus_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=%s", parodus_url_expected_value);
            return 1;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STRNE(parodus_url, parodus_url_expected_value);
    EXPECT_STRNE(seshat_url, seshat_url_expected_value);
    EXPECT_STRNE(build_type, build_type_expected_value);  
}

TEST_F(StartParodusTestFixture, get_url_seshat_url_strcpy_Fail)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "test_parodus_url";
    const char* seshat_url_expected_value = "test_seshat_url";
    const char* build_type_expected_value = "test_build_type" ;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(2)
        .WillOnce(Invoke([parodus_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=%s", parodus_url_expected_value);
            return 1;
        }))
        .WillOnce(Invoke([seshat_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SESHAT_URL=%s", seshat_url_expected_value);
            return 1;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(2)
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, parodus_url_expected_value);
    EXPECT_STRNE(seshat_url, seshat_url_expected_value);
    EXPECT_STRNE(build_type, build_type_expected_value);  
}

TEST_F(StartParodusTestFixture, get_url_build_type_strcpy_Fail)
{
    char parodus_url[64] = {'\0'};
    char seshat_url[64] = {'\0'};
	char build_type[16] = {'\0'};
    const char* parodus_url_expected_value = "test_parodus_url";
    const char* seshat_url_expected_value = "test_seshat_url";
    const char* build_type_expected_value = "test_build_type" ;

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed : Couldn't create temporary file";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(1)
        .WillOnce(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fscanf(mockFile, _, _))
        .Times(3)
        .WillOnce(Invoke([parodus_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "PARODUS_URL=%s", parodus_url_expected_value);
            return 1;
        }))
        .WillOnce(Invoke([seshat_url_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "SESHAT_URL=%s", seshat_url_expected_value);
            return 1;
        }))
        .WillOnce(Invoke([build_type_expected_value](FILE *file, const char *format, va_list args) {
            char *str = va_arg(args, char*);
            snprintf(str, 255, "BUILD_TYPE=%s", build_type_expected_value);
            return 1;
        }));

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(3)
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }))
        .WillOnce(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }))
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(1)
        .WillOnce(Return(0));
    
    get_url(parodus_url, seshat_url, build_type);
    EXPECT_STREQ(parodus_url, parodus_url_expected_value);
    EXPECT_STREQ(seshat_url, seshat_url_expected_value);
    EXPECT_STRNE(build_type, build_type_expected_value);  
}

// syncXpcParamsOnUpgrade
TEST_F(StartParodusTestFixture, syncXpcParamsOnUpgrade_Success)
{
    int ret = -1;
    const char *paramList[] = {"X_COMCAST-COM_CMC","X_COMCAST-COM_CID","X_COMCAST-COM_SyncProtocolVersion"};
    const char* lastRebootReason = "Software_upgrade";
    const char *firmwareVersion = "test_version";
    cJSON* mockJson = new cJSON();
    mockJson->type = cJSON_String;
    mockJson->valuestring = strdup("test_fw_version");
    const char* pathPrefix  = "eRT.com.cisco.spvtg.ccsp.webpa.";

    FILE* mockFile = tmpfile();
    ASSERT_NE(mockFile, nullptr) << "tmpfile() Failed: Couldn't create temporary file";

    const char* mockJsonContent = "{\"someKey\": \"someValue\"}";
    size_t mockJsonSize = strlen(mockJsonContent);

    const char* CMC_value = "testCMC_value";
    const char* CID_value = "testCID_value";
    const char* SyncProtocolVersion_value = "testSyncProtocolVersion_value";

    EXPECT_CALL(*g_fopenMock, fopen_mock(_, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_END))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, ftell(mockFile))
        .Times(1)
        .WillOnce(Return(mockJsonSize));

    EXPECT_CALL(*g_fileIOMock, fseek(mockFile, 0, SEEK_SET))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, fread(_, 1, mockJsonSize, mockFile))
        .Times(1)
        .WillOnce(Invoke([&](void *ptr, size_t size, size_t count, FILE *stream) {
            memcpy(ptr, mockJsonContent, mockJsonSize);
            return mockJsonSize;
        }));

    EXPECT_CALL(*g_fileIOMock, fclose(mockFile))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Return(0));
    
    EXPECT_CALL(*g_cjsonMock, cJSON_Parse(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_GetObjectItem(_, _))
        .Times(2)
        .WillRepeatedly(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_Print(_))
#ifndef UPDATE_CONFIG_FILE
        .Times(1)
        .WillOnce(Return(strdup(mockJsonContent)));
#else
        .Times(2)
        .WillOnce(Return(strdup(mockJsonContent)))
        .WillOnce(Return(strdup("newFirmware")));
#endif

#ifdef UPDATE_CONFIG_FILE
    EXPECT_CALL(*g_cjsonMock, cJSON_CreateString(_))
        .Times(1)
        .WillOnce(Return(mockJson));

    EXPECT_CALL(*g_cjsonMock, cJSON_ReplaceItemInObject(_, _, _))
        .Times(1)
        .WillOnce(Return(1));
#endif

    EXPECT_CALL(*g_cjsonMock, cJSON_Delete(_))
        .Times(1)
        .WillOnce(Invoke([](cJSON* json) {
            if (json && json->valuestring) {
                free(json->valuestring);
            }
            delete json;
        }));

    EXPECT_CALL(*g_safecLibMock, _sprintf_s_chk(_, _, _, _))
        .Times(::testing::AnyNumber())
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s %s", pathPrefix, "param1");
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s %s", pathPrefix, "param2");
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s %s", pathPrefix, "param3");
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli get -e %sparam1 %sparam2 %sparam3", pathPrefix, pathPrefix, pathPrefix);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &paramList, &CMC_value](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, paramList[0], CMC_value);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &paramList, &CID_value](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, paramList[1], CID_value);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &paramList, &SyncProtocolVersion_value](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, " %s%s %s", pathPrefix, paramList[2], SyncProtocolVersion_value);
            return strlen(buf);
        }))
        .WillOnce(Invoke([pathPrefix, &paramList, &CMC_value, &CID_value,  &SyncProtocolVersion_value](char* buf, size_t size, size_t n, const char* format, ...) {
            snprintf(buf, size, "psmcli set %s%s %s %s%s %s %s%s %s", pathPrefix, paramList[0], CMC_value, pathPrefix, paramList[1], CID_value, pathPrefix, paramList[2], SyncProtocolVersion_value);  // Command prefix or extra formatting
            return strlen(buf);
        }));

    EXPECT_CALL(*g_fileIOMock, popen(_, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Return(mockFile));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(::testing::AnyNumber())
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "0X=\"testCMC_PsmDb\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "1X=\"testCID_PsmDb\"\n", size);
            return buf;
        }))
        .WillOnce(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "2X=\"testSyncProtocolVersion_PsmDb\"\n", size);
            return buf;
        }))
        .WillRepeatedly(Invoke([](char* buf, int size, FILE* file) {
            strncpy(buf, "100\n", size);
            return buf;
        }));

    EXPECT_CALL(*g_fileIOMock, pclose(_))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Return(0));

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(0), Return(0)));


    EXPECT_CALL(*g_syscfgMock, syscfg_get(_, _, _, _))
        .WillOnce(DoAll(
            SetArrayArgument<2>(CMC_value, CMC_value + strlen(CMC_value) + 1),
            Return(0)
        ))
        .WillOnce(DoAll(
            SetArrayArgument<2>(CID_value, CID_value + strlen(CID_value) + 1),
            Return(0)
        ))
        .WillOnce(DoAll(
            SetArrayArgument<2>(SyncProtocolVersion_value, SyncProtocolVersion_value + strlen(SyncProtocolVersion_value) + 1),
            Return(0)
        ));

    
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Invoke([](char* dest, size_t destSize, const char* src, size_t srcSize) {
            strncpy(dest, src, destSize);
            return 0;
        }));
    
    ret = syncXpcParamsOnUpgrade(const_cast<char*>(lastRebootReason), const_cast<char*>(firmwareVersion));
    ASSERT_EQ(ret, 0);
}
