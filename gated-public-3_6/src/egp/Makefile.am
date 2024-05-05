#
# Makefile.am for EGP
#
PKGNAME = egp
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libegp.a
LIB_SRCS = egp.c egp_init.c egp_mib.c egp_rt.c
LIB_HDRS = egp.h egp_param.h
libegp_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

