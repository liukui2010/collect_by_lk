ARCH = $(shell uname)

ifeq ($(ARCH),SunOS)
ARCH = $(PLATFORM)

PROCESSOR = "$(shell uname -p)"
ifeq ($(PROCESSOR),i386)
ARCH = i86pc
endif

endif

RTTDIR = ./src/rtt
OBJDIR = ./obj/$(ARCH)
LIBDIR = ./lib/$(ARCH)
UTILSDIR = ./src/utils

all:  library utils

library:
	(cd $(RTTDIR) ; gmake)

utils:
	(cd $(UTILSDIR) ; gmake)

clean:
	(cd $(RTTDIR) ; gmake clean)
