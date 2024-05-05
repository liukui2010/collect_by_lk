#
# Makefile.am for SCRAM.
#
PKGNAME = scram
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libscram.a
LIB_SRCS = scram.c
LIB_HDRS = scram.h
libscram_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

