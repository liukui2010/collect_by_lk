#
# Makefile.am for krt_ipmulti.
#
PKGNAME = krt_ipmulti
AUTOMAKE_OPTIONS = no-dependencies
LIB_SRCS = krt_ipmulti_nocache.c
noinst_LIBRARIES = libkrt_multi.a
libkrt_multi_a_SOURCES = $(LIB_SRCS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../compat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@
