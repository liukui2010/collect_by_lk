#
# Makefile.am for GateD-core.
#
PKGNAME=gated-core
AUTOMAKE_OPTIONS = no-dependencies 
YFLAGS= -d -v
noinst_LIBRARIES = libstandalone.a
noinst_PROGRAMS = filter
sbin_PROGRAMS = gated

LIB_SRCS = checksum.c grand.c if.c parse.c policy.c ptree.c rt_aggregate.c \
		rt_mib.c rt_radix.c rt_redirect.c rt_static.c rt_table.c \
		sockaddr.c str.c targets.c task.c trace.c standalone.c \
		str.c checksum.c filter.c

libstandalone_a_SOURCES = standalone.c str.c checksum.c

filter_SOURCES=filter.c

EXTRA_gated_SOURCES= parser.y.unf
GATED_HDRS = defs.h	\
	gqueue.h	\
	if.h		\
	include.h	\
	linux.h		\
	list.h		\
	lrtimer.h	\
	paths.h		\
	parse.h		\
	parser.h	\
	policy.h	\
	ptree.h		\
	rt_table.h	\
	rt_var.h	\
	sockaddr.h	\
	str.h		\
	targets.h	\
	task.h		\
	trace.h		\
	unix.h

gated_SOURCES = $(GATED_HDRS) \
	parser.y	\
	checksum.c	\
	grand.c		\
	if.c		\
	lexer.l		\
	lrtimer.c	\
	parse.c		\
	policy.c	\
	ptree.c		\
	rt_aggregate.c	\
	rt_mib.c	\
	rt_radix.c	\
	rt_redirect.c	\
	rt_static.c	\
	rt_table.c	\
	sockaddr.c	\
	str.c		\
	targets.c	\
	task.c		\
	trace.c		\
	version.c

gated_LDADD = @GATED_LDADD@
gated_DEPENDENCIES = @GATED_DEPEND@
REMOVE_SUBDIRS = @REMOVE_SUBDIRS@

INCLUDES = -I. -I@srcdir@/../gated -I@srcdir@/../gatedcompat -I@srcdir@/..

BUILT_SOURCES = paths.h

parser.y: ${srcdir}/parser.y.unf ${top_builddir}/src/gated/filter ${top_builddir}/src/gated/options 
	./filter ${srcdir} < ${srcdir}/parser.y.unf > parser.y

stamp-remdirs:
	@( for d in $(REMOVE_SUBDIRS); do	\
		rm -rf ../$$d; done)
	touch stamp-remdirs

MKDEP = @MKDEP@
@MKDEP_FILE@

