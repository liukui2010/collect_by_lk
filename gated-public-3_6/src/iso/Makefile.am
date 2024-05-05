#
# Makefile.am for ISO.
#
PKGNAME = iso
AUTOMAKE_OPTIONS = no-dependencies 
LIB_SRCS = iso.c
LIB_HDRS = iso.h
noinst_LIBRARIES = libiso.a
libiso_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

