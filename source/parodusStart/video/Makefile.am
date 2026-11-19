##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
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
bin_PROGRAMS = startParodusMain

startParodusMain_SOURCES = startParodus.cpp

if RDK_SUPPORT_PARODUS
startParodusMain_SOURCES += \
    tr69hostif-rdk/tr69hostif/rdk_tr69hostif.cpp
else
startParodusMain_SOURCES += \
    startParodus_spport.cpp
endif

startParodusMain_LDADD = -lcjson -lsecure_wrapper -lwdmp-c -lrfcapi -lglib-2.0
AM_CXXFLAGS = -I$(top_srcdir)/include \
              -I$(top_srcdir)/src/hostif/include  \
              -I$(top_srcdir)/src/hostif/handlers/include \
              -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/wdmp-c \
               $(GLIB_CFLAGS) $(G_THREAD_CFLAGS)
