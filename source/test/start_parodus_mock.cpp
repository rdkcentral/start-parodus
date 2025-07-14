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

#include <gmock/gmock.h>
#include "start_parodus_mock.h"

SafecLibMock * g_safecLibMock = NULL;
SyscfgMock * g_syscfgMock = NULL;
PlatformHalMock * g_platformHALMock = NULL;
utopiaMock * g_utopiaMock = NULL;
SyseventMock * g_syseventMock = NULL;
CmHalMock * g_cmHALMock = NULL;
cjsonMock * g_cjsonMock = NULL;
FileIOMock * g_fileIOMock = NULL;

StartParodusBaseTestFixture::StartParodusBaseTestFixture()
{
    g_safecLibMock = new SafecLibMock;
    g_syscfgMock = new SyscfgMock;
    g_platformHALMock = new PlatformHalMock;
    g_utopiaMock = new utopiaMock;
    g_syseventMock = new SyseventMock;
    g_cmHALMock = new CmHalMock;
    g_cjsonMock = new cjsonMock;
    g_fileIOMock = new FileIOMock;
}

StartParodusBaseTestFixture::~StartParodusBaseTestFixture()
{
    delete g_safecLibMock;
    delete g_syscfgMock;
    delete g_platformHALMock;
    delete g_utopiaMock;
    delete g_syseventMock;
    delete g_cmHALMock;
    delete g_cjsonMock;
    delete g_fileIOMock;

    g_safecLibMock = nullptr;
    g_syscfgMock = nullptr;
    g_platformHALMock = nullptr;
    g_utopiaMock = nullptr;
    g_syseventMock = nullptr;
    g_cmHALMock = nullptr;
    g_cjsonMock = nullptr;
    g_fileIOMock = nullptr;
}

void StartParodusBaseTestFixture::SetUp() {}
void StartParodusBaseTestFixture::TearDown() {}
void StartParodusBaseTestFixture::TestBody() {}

// end of file
