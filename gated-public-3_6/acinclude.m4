
dnl AC_CHOOSE_FUNC(VARIABLE, VAR-TO-CHECK-FOR)
AC_DEFUN(AC_CHOOSE_FUNC,
[AC_CACHE_VAL(ac_cv_choose_func_$1,
[for ac_func in $2
do
   AC_CHECK_FUNC([$]ac_func, $1=$ac_func)
   test -n "[$]$1" && break
done
])dnl
AC_DEFINE_UNQUOTED($1,[$]$1)dnl
])

dnl AC_KERNEL_VAR(VARIABLE, VAR-TO-CHECK-FOR)
AC_DEFUN(AC_KERNEL_VAR,
[AC_CACHE_VAL(ac_cv_kernel_var_$1,
[if test -n "[$]$1"; then
  ac_cv_prog_$1="[$]$1" # Let the user override the test.
else
   if test ! -f /tmp/kernel.nm; then
      nm $ac_cv_path_kernel > /tmp/kernel.nm
   fi
   if egrep "^$2 " /tmp/kernel.nm >/dev/null 2>&1; then
      ac_cv_kernel_var_$1="$2"
   else
      if egrep " $2\$" /tmp/kernel.nm >/dev/null 2>&1; then
         ac_cv_kernel_var_$1="$2"
      fi
   fi
fi
])dnl
$1="$ac_cv_kernel_var_$1"
dnl AC_SUBST($1)dnl
AC_DEFINE_UNQUOTED($1,"$ac_cv_kernel_var_$1")dnl
])

dnl AC_KERNEL_VARS(VARIABLE, VARS-TO-CHECK-FOR [, VALUE-IF-NOT-FOUND])
dnl example: AC_KERNEL_VARS(KERNEL_TCP_TTL, _tcp_ttl, tcp_ttl)
AC_DEFUN(AC_KERNEL_VARS,
[AC_MSG_CHECKING([for $1])
for ac_var in $2
do
   AC_KERNEL_VAR($1, [$]ac_var)
   test -n "[$]$1" && break
done
ifelse([$3], , , [test -n "[$]$1" || $1="$3"])
test -n "$ac_cv_kernel_var_$1" || ac_cv_kernel_var_$1=unknown
AC_DEFINE_UNQUOTED($1,"$ac_cv_kernel_var_$1")dnl
if test -n "[$]$1"; then
  AC_MSG_RESULT([$]$1)
else
  AC_MSG_RESULT(no)
fi
])

AC_DEFUN(AC_LLADDR_TYPE,
[
 AC_KERNEL_VARS(KSYM_IFNET, _ifnet ifnet, unknown)
 dnl Tell what we are looking for
 AC_MSG_CHECKING(which lladdr system is being used)
 AC_CACHE_VAL(ac_cv_lladdr_type,
[

 dnl Default value
AC_EGREP_HEADER(arpcom, netinet/if_ether.h, use_arpcom="yes", use_arpcom="no")
 if test "$ac_cv_file_dev_nit" = "yes"; then
    ac_cv_lladdr_type=SUNOS4
 else
    if test "$ac_cv_hdr_SIOCGIFHWADDR" = "yes"; then
	ac_cv_lladdr_type=LINUX
    else
	if test "$ac_cv_hdr_DL_HP_PPA_ACK" = "yes"; then
		ac_cv_lladdr_type=HPSTREAMS
	else
		if test "$ac_cv_header_sys_dlpi_h" = "yes"; then
			ac_cv_lladdr_type=SUNOS5
		else
			if test "$use_arpcom" = "yes"; then
				ac_cv_lladdr_type=KMEM
			else
				ac_cv_lladdr_type=NONE
			fi
		fi
	fi
   fi
 fi
])dnl
AC_DEFINE_UNQUOTED(KVM_TYPE,"$ac_cv_lladdr_type")dnl

   dnl Define separate flags
   if test $ac_cv_lladdr_type = "HPSTREAMS"; then
      AC_DEFINE(KRT_LLADDR_HPSTREAMS)
   else
      if test $ac_cv_lladdr_type = "SUNOS4"; then
         AC_DEFINE(KRT_LLADDR_SUNOS4)
      else
         if test $ac_cv_lladdr_type = "SUNOS5"; then
            AC_DEFINE(KRT_LLADDR_SUNOS5)
         else
            if test $ac_cv_lladdr_type = "LINUX"; then
               AC_DEFINE(KRT_LLADDR_LINUX)
            else
               if test $ac_cv_lladdr_type = "KMEM"; then
                  AC_DEFINE(KRT_LLADDR_KMEM)
	       else
                  AC_DEFINE(KRT_LLADDR_NONE)
               fi
            fi
         fi
      fi
   fi

   dnl Show result
   AC_MSG_RESULT($ac_cv_lladdr_type)
])

AC_DEFUN(AC_KVM_TYPE,
[
 AC_CHECK_LIB(kvm, kvm_read)
 AC_CHECK_FUNCS(kvm_openfiles kvm_nlist)
 dnl Tell what we are looking for
 AC_MSG_CHECKING(which kvm system is being used)
 AC_CACHE_VAL(ac_cv_kvm_type,
[

 dnl Default value
 ac_cv_kvm_type=NONE

 if test $ac_cv_func_kvm_openfiles = yes; then
    if test $ac_cv_func_kvm_nlist = yes; then
       ac_cv_kvm_type=BSD44
    else
       ac_cv_kvm_type=OTHER
    fi
 else
    if test $ac_cv_func_kvm_open = yes -o $ac_cv_lib_kvm_kvm_open = yes; then
       ac_cv_kvm_type=SUNOS4
    fi
 fi
])dnl
AC_DEFINE_UNQUOTED(KVM_TYPE,"$ac_cv_kvm_type")dnl

   dnl Define separate flags
   if test $ac_cv_kvm_type = "BSD44"; then
      AC_DEFINE(KVM_TYPE_BSD44)
   else
      if test $ac_cv_kvm_type = "SUNOS4"; then
         AC_DEFINE(KVM_TYPE_SUNOS4)
      else
         if test $ac_cv_kvm_type = "RENO"; then
            AC_DEFINE(KVM_TYPE_RENO)
         else
	    dnl
	    dnl HP-UX 11 and digital need all kvm compat objs
	    dnl 
            if test $ac_cv_kvm_type != "NONE" -o $ac_cv_lladdr_type = "HPSTREAMS" -o $digital_unix = yes; then
	       ac_cv_kvm_type=OTHER
               AC_DEFINE(KVM_TYPE_OTHER)
	       LIBOBJS="$LIBOBJS kvm.o"
            else
               AC_DEFINE(KVM_TYPE_NONE)
            fi
         fi
      fi
   fi

   dnl Show result
   AC_MSG_RESULT($ac_cv_kvm_type)
])

dnl Will generate signames.h from signal.h
AC_DEFUN(AC_SYS_SIGNAME,
[
AC_CHECK_FUNCS(sys_signame)
if test "x$ac_cv_func_sys_signame" = "xno"; then
	sigfile='configure'
	if grep SIGINT /usr/include/signal.h > /dev/null; then
		sigfile=/usr/include/signal.h
	elif grep SIGINT /usr/include/sys/signal.h > /dev/null; then
		sigfile=/usr/include/sys/signal.h
	elif grep SIGINT /usr/include/asm/signal.h > /dev/null; then
		# Linux keeps signal.h in a different spot
		sigfile=/usr/include/asm/signal.h
	elif grep SIGINT /usr/include/sys/iso/signal_iso.h > /dev/null; then
		sigfile=/usr/include/sys/iso/signal_iso.h
	fi
	signamesfile=signames.h
	ifelse([$1], , , [signamesfile=$1])

# The following doesn't work.  ac_dir is left equal to signamesfile.
# Need to fix this eventually so we can delete the "mkdir -p" command 
# from configure.in.
#
#   # Remove last slash and all that follows it.  Not all systems have dirname.
#   ac_dir=`echo $signamesfile|sed 's%/[^/][^/]*$%%'`
#   if test "$ac_dir" != "$signamesfile" && test "$ac_dir" != .; then
#    # The file is in a subdirectory.
#    test ! -d "$ac_dir" && mkdir -p "$ac_dir"
#   fi

   echo "/* This file is automatically generated from $sigfile */" > $signamesfile
   cat >> $signamesfile << EOM
const char *const sys_signame[[]] = {
EOM
   count=1
   if test $sigfile = "configure"; then
      while test $count -le 64; do
         echo "    \"Signal $count\",      /* $Signal $count */" >> $signamesfile
         count=`expr $count + 1`
      done
   else
      grep 'define[[ 	]]*SIG' $sigfile | while read line; do
         set $line
         if test "x[$]3" != "x$count"; then
            continue
         fi
         echo "    \"[$]2\",	/* [$]3 */" >> $signamesfile
         count=`expr $count + 1`
      done
   fi
   echo "};" >> $signamesfile
fi
])

dnl Read $1 and output $2
AC_DEFUN(AC_FILTER_FILE,
[
   infile=$1
   outfile=$2
   ok=1
   level=1
   while read line; do
      set $line
      if test "x$1" = "x@BEGIN:"; then
         level=`expr $level + 1`
         echo "BEGIN: $2"
      else 
         if test "x$1" = "x@END:"; then
            echo "END: $2"
            level=`expr $level - 1`
         else
            if test $ok = "1"; then
               echo $line
            fi
         fi
      fi
   done < $infile 
])

AC_DEFUN(AC_VERSION_INFO,
[
   BUILD_DATE=`date`
   AC_SUBST(BUILD_DATE)
])

dnl AC_CHECK_HEADER_DEFINE(PATTERN, HEADER-FILE, ACTION-IF-FOUND [,
dnl                 ACTION-IF-NOT-FOUND])
AC_DEFUN(AC_CHECK_HEADER_DEFINE,
[AC_MSG_CHECKING(whether $2 defines $1)
AC_CACHE_VAL(ac_cv_hdr_$1,
[AC_EGREP_CPP(yes, [#include <$2>
#ifdef $1
yes
#endif
], [ac_cv_hdr_$1=yes], [ac_cv_hdr_$1=no])
])
if test "$ac_cv_hdr_$1" = yes; then
   $3
ifelse([$4], , , [else
   $4
])dnl
fi
AC_MSG_RESULT($ac_cv_hdr_$1)
])

dnl Define UNUSED to __unused__ if the compiler accepts the __unused__ keyword.
dnl Otherwise define UNUSED to __attribute__((__unused__)) if that works.
dnl otherwise define UNUSED to be empty.
AC_DEFUN(AC_C_UNUSED,
[AC_CACHE_CHECK([for UNUSED], ac_cv_c_unused,
[ac_cv_c_unused=no
for ac_kw in unused __unused__ '__attribute__((__unused__))'; do
  AC_TRY_COMPILE(, [} $ac_kw foo() {], [ac_cv_c_unused=$ac_kw; break])
done
])
case "$ac_cv_c_unused" in
  inline | yes) ;;
  no) AC_DEFINE(UNUSED, ) ;;
  *)  AC_DEFINE_UNQUOTED(UNUSED, $ac_cv_c_unused) ;;
esac
])

dnl AC_CHECK_DIR(VARIABLE, DIRECTORY_LIST)
AC_DEFUN(AC_CHECK_DIR,
[AC_MSG_CHECKING(which directory to use for $1)
AC_CACHE_VAL(ac_cv_dir_$1,
[for ac_var in $2; do
   if test -d $ac_var; then
      ac_cv_dir_$1="$ac_var"
      break
   fi
done
])
$1="$ac_cv_dir_$1"
dnl AC_DEFINE_UNQUOTED($1,"$ac_cv_kernel_var_$1")dnl
AC_SUBST($1)
AC_MSG_RESULT($ac_cv_dir_$1)
])
