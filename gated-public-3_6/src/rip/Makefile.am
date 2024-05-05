#
# Makefile.am for RIP.
#
PKGNAME = rip
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = librip.a
LIB_SRCS = rip.c rip_mib.c
LIB_HDRS = rip.h
librip_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

