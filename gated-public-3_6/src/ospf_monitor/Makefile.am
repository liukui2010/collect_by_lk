#
# Makefile.am for ospf_monitor.
#
PKGNAME = ospf_monitor
AUTOMAKE_OPTIONS = no-dependencies 
noinst_PROGRAMS = ospf_monitor
LIB_SRCS = ospf_monitor.c
ospf_monitor_SOURCES = $(LIB_SRCS)
ospf_monitor_LDADD = -L../gated -lstandalone
ospf_monitor_DEPENDENCIES = ../gated/libstandalone.a
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/.. -I@srcdir@/../ospf
MKDEP = @MKDEP@

#
# MKDEP_FILEXXX
# figure out why mkdep doesn't work here
#
depend:
	@echo ""
