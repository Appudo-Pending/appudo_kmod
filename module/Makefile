###########################################################################################
#    Makefile is part of Appudo
#
#    Copyright (C) 2015-2016
#        a742baed6b4bbfbc5c50dfea489f8dc0976855df1a27fb4662ce2cc5123dcc1a source@appudo.com
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 3, or (at your option)
#    any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, 51 Franklin Street - Fifth Floor, Boston,
#    MA 02110-1301, USA.
###########################################################################################


OS_TYPE := $(shell uname -s)
OS_ARCH := $(shell uname -m)

TARGET = eventpoll-ex

EXTRA_CFLAGS += -I${PWD}/include -DNDEBUG 
#-fsanitize=kernel-address -g3 -O1
KERNEL_SRC := /lib/modules/`uname -r`/build

obj-m += $(TARGET).o
eventpoll-ex-objs := eventpoll.o fs/locks.o

all:
	make -C $(KERNEL_SRC) M=$(PWD) modules

install: all
	mkdir -p /lib/modules/`uname -r`/misc
	cp eventpoll-ex.ko /lib/modules/`uname -r`/misc/
	depmod -a `uname -r`
	insmod eventpoll-ex.ko

uninstall:
	rmmod eventpoll-ex

clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean
	rm -rf fs/locks.o eventpoll.o eventpoll-ex.o eventpoll-ex.ko eventpoll-ex.mod.c eventpoll-ex.mod.o modules.order Module.symvers .eventpoll-ex.ko.cmd .eventpoll-ex.mod.o.cmd .eventpoll-ex.o.cmd .tmp_versions
