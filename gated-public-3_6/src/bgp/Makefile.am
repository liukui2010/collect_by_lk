#
# Makefile.am for BGP.
#
PKGNAME = bgp
noinst_LIBRARIES = libbgp.a
AUTOMAKE_OPTIONS = no-dependencies
LIB_SRCS = bgp.c bgp_rt.c bgp_init.c bgp_sync.c
LIB_HDRS = bgp.h bgp_proto.h bgp_var.h
libbgp_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../compat -I@srcdir@/.. 
MKDEP = @MKDEP@
@MKDEP_FILE@
