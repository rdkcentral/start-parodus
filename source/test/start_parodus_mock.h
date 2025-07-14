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

#ifndef START_PARODUS_MOCK_H
#define START_PARODUS_MOCK_H

#include "gtest/gtest.h"

#include <mocks/mock_safec_lib.h>
#include <mocks/mock_syscfg.h>
#include <mocks/mock_platform_hal.h>
#include <mocks/mock_utopia.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_cm_hal.h>
#include <mocks/mock_cJSON.h>
#include <mocks/mock_file_io.h>

class StartParodusBaseTestFixture : public ::testing::Test {
  protected:
        SafecLibMock mockedSafecLibMock;
        SyscfgMock mockedSyscfg;
        PlatformHalMock mockedPlatformHal;
        utopiaMock mockedUtopia;
        SyseventMock mockedSysEvent;
        CmHalMock mockedCmHal;
        cjsonMock mockedCjson;
        FileIOMock mockedFileIO;

        StartParodusBaseTestFixture();
        virtual ~StartParodusBaseTestFixture();
        virtual void SetUp() override;
        virtual void TearDown() override;

        void TestBody() override;
};

#endif