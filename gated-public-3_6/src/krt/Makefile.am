#
# Makefile.am for krt.
#
PKGNAME = krt
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libkrt.a
LIB_SRCS = krt.c
LIB_HDRS = krt.h krt_var.h
libkrt_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

