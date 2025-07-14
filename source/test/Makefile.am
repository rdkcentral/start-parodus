##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -g -Werror -fPIC -fno-exceptions -Os -Wextra
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = parodusStart_gtest.bin

parodusStart_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                  -I${top_srcdir}/gtest/include \
                                  -I${top_srcdir}/source \
                                  -I${top_srcdir}/source/include

# Add preprocessor definitions for unit testing with Docker support.
parodusStart_gtest_bin_CPPFLAGS += -DUNIT_TEST_DOCKER_SUPPORT -DUPDATE_CONFIG_FILE

parodusStart_gtest_bin_SOURCES =  gtest_main.cpp \
                                  $(top_srcdir)/source/parodusStart/start_parodus.c \
                                  start_parodus_test.cpp \
                                  start_parodus_mock.cpp

parodusStart_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread

parodusStart_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_safec_lib.la \
                               $(HOME)/usr/local/lib/libmock_syscfg.la \
                               $(HOME)/usr/local/lib/libmock_file_io.la \
                               $(HOME)/usr/local/lib/libmock_sysevent.la \
                               $(HOME)/usr/local/lib/libmock_cjson.la \
                               $(HOME)/usr/local/lib/libmock_platform_hal.la \
                               $(HOME)/usr/local/lib/libmock_cm_hal.la \
                               $(HOME)/usr/local/lib/libmock_utopia.la

# Adding Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
parodusStart_gtest_bin_LDFLAGS += --coverage