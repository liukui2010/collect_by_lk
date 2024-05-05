#
# Makefile.am for SLSP
#
PKGNAME = slsp
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libslsp.a
LIB_HDRS = slsp.h slsp_proto.h slsp_var.h
LIB_SRCS = slsp_db.c slsp_init.c slsp_io.c slsp_mib.c slsp_nbr.c slsp_rt.c
libslsp_a_SOURCES = $(LIB_HDRS) $(LIB_SRCS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..

MKDEP = @MKDEP@
@MKDEP_FILE@

