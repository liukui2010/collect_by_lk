# Makefile for the Utilities for RT Threads

ARCH = $(shell uname)
PROCESSOR = "$(shell uname -p)"

ifeq ($(ARCH), SunOS)
ARCH = $(PLATFORM)

ifeq ($(PROCESSOR),i386)
ARCH = i86pc
endif
endif

ROOTDIR = ../..

RTTINC = $(ROOTDIR)/include

SD = .
OD = $(ROOTDIR)/obj/$(ARCH)
LD = $(ROOTDIR)/lib/$(ARCH)

ifeq ($(ARCH),ibm)
  CC = xlc -D_ALL_SOURCE
else
  CC = gcc
endif
 
# compile options
INCLUDES = -I. -I$(RTTINC)
CFLAGS = -g $(INCLUDES)


OBJS = $(OD)/RttBarrier.o $(OD)/RttCommon.o $(OD)/RttMutex.o $(OD)/RttQueue.o

all:	lib

lib:	$(OBJS) $(LD)/libRttUtils.a

$(LD)/libRttUtils.a: $(OBJS)
	ar rc $(LD)/libRttUtils.a $(OBJS)
	-@chmod ug+w $(LD)/libRttUtils.a
ifneq ($(ARCH),sun4sol)
	ranlib $(LD)/libRttUtils.a
endif

install:
	cp RttBarrier.h $(RTTINC)
	-@chmod ug+w $(RTTINC)/RttBarrier.h
	cp RttCommon.h $(RTTINC)
	-@chmod ug+w $(RTTINC)/RttCommon.h
	cp RttMutex.h $(RTTINC)
	-@chmod ug+w $(RTTINC)/RttMutex.h
	cp RttQueue.h $(RTTINC)
	-@chmod ug+w $(RTTINC)/RttQueue.h

clean:
	rm -f *~ #* $(OBJS) $(LD)/libRttUtils.a

$(OD)/RttBarrier.o: $(SD)/RttBarrier.c
	$(CC) $(CFLAGS) -c $(SD)/RttBarrier.c -o $(OD)/RttBarrier.o

$(OD)/RttCommon.o: $(SD)/RttCommon.c
	$(CC) $(CFLAGS) -c $(SD)/RttCommon.c -o $(OD)/RttCommon.o

$(OD)/RttMutex.o: $(SD)/RttMutex.c
	$(CC) $(CFLAGS) -c $(SD)/RttMutex.c -o $(OD)/RttMutex.o

$(OD)/RttQueue.o: $(SD)/RttQueue.c
	$(CC) $(CFLAGS) -c $(SD)/RttQueue.c -o $(OD)/RttQueue.o



