#
# Makefile.am for ICMP.
#
PKGNAME = icmp
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libicmp.a
LIB_SRCS = icmp.c
LIB_HDRS = ip_icmp.h icmp.h
libicmp_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

