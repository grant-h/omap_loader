# OMAP Loader Makefile
#   Written by Grant Hernandez
CC=gcc

INCLUDEDIR=$(shell pkg-config --cflags libusb-1.0)
LIBS=$(shell pkg-config --libs libusb-1.0)

CFLAGS=-Wall -O2 $(INCLUDEDIR)
LDFLAGS=
EXECNAME=omap_loader

SRCS=omap_loader.c
OBJS = $(SRCS:.c=.o)

ifdef CROSS_COMPILE
  CC := $(CROSS_COMPILE)$(CC)
  CXX := $(CROSS_COMPILE)$(CC)
endif

all:	$(OBJS)
	$(CC) $(LDFLAGS) -o $(EXECNAME) $(OBJS) $(LIBS)

clean:
	-rm -f *.o $(EXECNAME)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
