#
# Makefile.am for SMUX.
#
PKGNAME = smux
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libsmux.a
LIB_SRCS = smux.c smux_asn1.c smux_snmp.c
LIB_HDRS = smux.h smux_asn1.h smux_snmp.h
libsmux_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@
