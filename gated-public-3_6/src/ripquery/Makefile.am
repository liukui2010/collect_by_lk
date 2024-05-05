#
# Makefile.am for ripquery.
#
PKGNAME = ripquery
AUTOMAKE_OPTIONS = no-dependencies 
noinst_PROGRAMS = ripquery
LIB_SRCS = ripquery.c
ripquery_SOURCES = $(LIB_SRCS)
ripquery_LDADD = -L../gated -lstandalone
ripquery_DEPENDENCIES = ../gated/libstandalone.a
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

