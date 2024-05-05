#
# Makefile.am for GII.
#
PKGNAME = gii
AUTOMAKE_OPTIONS = no-dependencies
noinst_LIBRARIES = libgii.a
LIB_SRCS = gii.c
LIB_HDRS = gii.h
libgii_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@
