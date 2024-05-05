#
# Makefile.am for aspaths.
#
PKGNAME = aspath
noinst_LIBRARIES = libaspath.a
AUTOMAKE_OPTIONS = no-dependencies
LIB_SRCS = asmatch.c aspath.c
LIB_HDRS = asmatch.h aspath.h
libaspath_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/.. -I@srcdir@/../gated -I@srcdir@/../compat
MKDEP = @MKDEP@
@MKDEP_FILE@
