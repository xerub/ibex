#  ibex - main makefile
#
#  Copyright (c) 2010, 2014-2015 xerub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


.PHONY: all clean distclean

GNUARM_PREFIX ?= /opt/gnuarm/bin/arm-none-eabi-
#TARGET ?= iPad3,1/11D257/iBoot
#TARGET ?= iPhone3,1/11D257/iBoot
#TARGET ?= iPhone4,1/11D257/iBoot
#TARGET ?= iPhone5,2/11B554a/iBoot
#PIE = 1

CC = $(GNUARM_PREFIX)gcc
CFLAGS = -Wall -W -pedantic
CFLAGS += -Wno-long-long
CFLAGS += -Os
#CFLAGS += -mthumb -march=armv6
CFLAGS += -fcall-used-r9

LD = $(GNUARM_PREFIX)gcc
LDFLAGS = -L. -nostdlib
LDFLAGS += -Tscript.ld
LDLIBS = -lp

AR = $(GNUARM_PREFIX)ar
ARFLAGS = crus

OBJCOPY = $(GNUARM_PREFIX)objcopy

ifeq ($(TARGET),)
CFLAGS += -fpie
else
include $(TARGET)/target.mak
endif
CFLAGS += -I.
#LDLIBS += -lgcc

SOURCES = \
	link.c \
	nand.c \
	blob.c \
	main.c

LIBSOURCES = \
	lib/atoi.c \
	lib/div.c \
	lib/memcmp.c \
	lib/memmem.c \
	lib/memmove.c \
	lib/memset.c \
	lib/strcmp.c \
	lib/xtoi.c

OBJECTS = $(SOURCES:.c=.o) cache.o
LIBOBJECTS = $(LIBSOURCES:.c=.o)

.S.o:
	$(CC) -o $@ $(CFLAGS) -c $<

.c.o:
	$(CC) -o $@ $(CFLAGS) -c $<

all: payload

payload: payload.elf
	$(OBJCOPY) -O binary $< $@

payload.elf: $(OBJECTS) | entry.o libp.a
	$(LD) -o $@ $(LDFLAGS) $^ $(LDLIBS)

libp.a: $(LIBOBJECTS)
	$(AR) $(ARFLAGS) $@ $^

clean:
	-$(RM) *.o *.elf *.a $(LIBOBJECTS)

distclean: clean
	-$(RM) payload

-include depend
