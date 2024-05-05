#
# Makefile.am for RDISC.
#
PKGNAME = rdisc
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = librdisc.a
LIB_SRCS = rdisc.c
LIB_HDRS = rdisc.h
librdisc_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

