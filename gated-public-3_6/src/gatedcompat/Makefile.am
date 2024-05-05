PKGNAME = gatedcompat
noinst_LIBRARIES = libgatedcompat.a
LIB_SRCS = IEFBR14.c flock.c herrs.c kvm.c strcasecmp.c sysconf.c \
		ffs.c h_errno.c inet_aton.c setvbuf.c strerror.c unsetenv.c
LIB_HDRS = include.h queue.h

#
# this is a hack because the above sources can't appear in
# libgatedcompat_SOURCES if they are not to be built.
#
libgatedcompat_a_SOURCES = IEFBR14.c include.h
libgatedcompat_a_LIBADD = @LIBOBJS@
EXTRA_DIST = flock.c herrs.c kvm.c strcasecmp.c sysconf.c ffs.c h_errno.c \
	inet_aton.c setvbuf.c strerror.c unsetenv.c queue.h
	
AUTOMAKE_OPTIONS = no-dependencies 
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..

MKDEP = @MKDEP@
@MKDEP_FILE@

