#
# Makefile.am for gdc.
#
PKGNAME = gdc
AUTOMAKE_OPTIONS = no-dependencies 
noinst_PROGRAMS = gdc
LIB_SRCS = gdc.c
gdc_SOURCES = $(LIB_SRCS)
gdc_LDADD = -L../gated -lstandalone -L../gatedcompat -lgatedcompat
gdc_DEPENDENCIES = ../gated/libstandalone.a
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

