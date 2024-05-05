#
# Makefile.am for OSPF.
#
PKGNAME = ospf
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libospf.a
LIB_SRCS = 	ospf_build_dbsum.c ospf_build_ls.c ospf_chksum.c \
		ospf_choose_dr.c ospf_conf.c ospf_flood.c \
		ospf_init.c ospf_log.c ospf_lsdb.c ospf_mib.c ospf_newq.c \
		ospf_rt.c ospf_rtab.c  ospf_rxlinkup.c ospf_rxmon.c ospf_rxpkt.c \
		ospf_spf.c ospf_spf_leaves.c ospf_states.c \
		ospf_tqhandle.c ospf_trace.c ospf_txpkt.c
LIB_HDRS = 	ospf.h ospf_const.h ospf_gated.h ospf_log.h ospf_pkts.h \
		ospf_timer_calls.h ospf_rtab.h ospf_lsdb.h
		
libospf_a_SOURCES = $(LIB_SRCS) $(LIB_HDRS)
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..
MKDEP = @MKDEP@
@MKDEP_FILE@

