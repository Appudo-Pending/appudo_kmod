###########################################################################################
#    appudo_kmod.pro is part of Appudo
#
#    Copyright (C) 2015
#       543699f52901235482e5b2c38ffc606366c05ce2c371043aecdbeff00215914a source@appudo.com
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
###########################################################################################

TEMPLATE = aux
DESTDIR = $$_PRO_FILE_PWD_/out
OBJECTS_DIR = $$DESTDIR/.obj

UNAME = $$system(uname -r)

INCLUDEPATH = /lib/modules/$$UNAME/source/include

DISTFILES += \
    module/Makefile \
    module/locks.h \
    module/eventpoll.h \
    module/eventpoll.c \
    module/fs/locks.c \
    module/fs/eventfd.c \
    module/fs/file.c \
    module/sock.c \
    module/group_cache.h \
    module/group_cache.c \
    module/debug_trace.h \
    module/debug_trace.c \
    module/mm/process_vm_access.c \
    linux-source-3.18.25.tar.bz2 \
    COPYING

first.commands = make -C /lib/modules/$$UNAME/build M=$$_PRO_FILE_PWD_/module modules
QMAKE_EXTRA_TARGETS += first

