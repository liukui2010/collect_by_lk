#
# Makefile.am for INETv4.
#
PKGNAME = inetv4
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libinet.a
LIB_SRCS = inet.c
LIB_HDRS = inet.h
libinet_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@
