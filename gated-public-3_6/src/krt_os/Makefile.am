#
# Makefile.am for krt_os.
#
PKGNAME = krt_os
AUTOMAKE_OPTIONS = no-dependencies 
noinst_LIBRARIES = libkrt_os.a
libkrt_os_a_SOURCES=

LIB_SRCS = krt_ifread_netlink.c \
	krt_ifread_combo.c \
	krt_ifread_ioctl.c \
	krt_ifread_kinfo.c \
	krt_lladdr_hpstreams.c \
	krt_lladdr_kmem.c \
	krt_lladdr_linux.c \
	krt_lladdr_sunos4.c \
	krt_lladdr_sunos5.c \
	krt_netopts.c \
	krt_rt_ioctl.c \
	krt_rt_sock.c \
	krt_rt_netlink.c \
	krt_rtread_hp10x.c \
	krt_rtread_hpstreams.c \
	krt_rtread_kinfo.c \
	krt_rtread_kmem.c \
	krt_rtread_proc.c \
	krt_rtread_netlink.c \
	krt_rtread_radix.c \
	krt_rtread_sunos5.c \
	krt_symbols_nlist.c \
	krt_symbols_proc.c \
	krt_symbols_sunos5.c \
	krt_symbols_sysctl.c
EXTRA_libkrt_os_a_SOURCES = $(LIB_SRCS)
libkrt_os_a_LIBADD = @LIBKRT_OS_A_LIBADD@
libkrt_os_a_DEPENDENCIES = @LIBKRT_OS_A_LIBADD@
INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..

MKDEP = @MKDEP@
@MKDEP_FILE@
