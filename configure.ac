###
### Copyright (C) JAEHYUK CHO
### All rights reserved.
### Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
###

AC_PREREQ([2.63])

AC_INIT(libhwport_ftpd, 0.0.1, minzkn (at) minzkn (dot) com)

AC_CONFIG_SRCDIR([hwport_ftpd.c])
AC_CONFIG_HEADERS([config.h:config.h.in])
#AC_CONFIG_MACRO_DIR(m4)

AM_INIT_AUTOMAKE([foreign])

AC_SUBST(LIBMZSEED_VERSION_INFO, [0:1:0])

AC_CANONICAL_HOST

AM_SILENT_RULES([yes])

AC_PREFIX_DEFAULT([/usr])

AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_LIBTOOL
AC_PROG_INSTALL
#AC_PROG_MAKE_SET

AC_CHECK_TYPES(ssize_t, , [AC_DEFINE([ssize_t], [signed long], [Define ssize_t if it is not done by the standard libs.])])
AC_CHECK_TYPES(size_t, , [AC_DEFINE([size_t], [long], [Define ssize_t if it is not done by the standard libs.])])

AC_C_CONST
AC_STRUCT_TM
AC_TYPE_SIGNAL
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_TYPE_INT64_T

AC_SYS_LARGEFILE

AC_CHECK_FUNCS()

AC_HEADER_STDC
AC_HEADER_TIME

AC_CHECK_HEADERS(
    [sys/types.h \
     sys/stat.h \
     sys/time.h \
     sys/socket.h \
     sys/un.h \
     sys/wait.h \
     netinet/ip.h \
     netinet/tcp.h \
     netinet/in.h \
     arpa/inet.h \
     stdio.h \
     stdlib.h \
     stdarg.h \
     memory.h \
     string.h \
     time.h \
     fcntl.h \
     errno.h \
     unistd.h \
     netdb.h \
     signal.h \
     dirent.h \
     netinet/in.h
])
#AC_CHECK_LIB([],[],,AC_MSG_ERROR([ not found!]))
	
#AC_ARG_ENABLE([ftpd],
#	AS_HELP_STRING([--enable-ftpd],
#	               [enable ftpd support [default=yes]]),
#	[ENABLE_FTPD=$enable_ftpd])
#if test $ENABLE_FTPD = yes; then
#	AC_DEFINE([ENABLE_FTPD],
#                  1, [ftpd support])
#fi

LIBS=""

#AC_CHECK_LIB(
#    [dl],
#    [dlopen],
#    LIBS="$LIBS -ldl",
#    AC_MSG_ERROR(
#        [need dl library]
#    )
#)

AC_CHECK_LIB(
    [pthread],
    [pthread_create],
    LIBS="$LIBS -lpthread",
    AC_MSG_ERROR(
        [need pthread library]
    )
)

AC_CHECK_LIB(
    [crypt],
    [crypt],
    [LIBS="$LIBS -lcrypt"
     AC_DEFINE(NEED_CRYPT, 1, [Do we need -lcrypt?])
    ],
    AC_MSG_ERROR(
        [need crypt library]
    )
)

AC_CONFIG_FILES([
makefile
])
AC_OUTPUT

cat <<EOF

$PACKAGE-$VERSION configuration summary:

    Install prefix .................. : ${prefix}
    C preprocessor .................. : ${CPP}
    C compiler ...................... : ${CC}
    C++ preprocessor ................ : ${CXXCPP}
    C++ compiler .................... : ${CXX}
    Linker .......................... : ${LD}
    C preprocessor flags ............ : ${CPPFLAGS}
    C compiler flags ................ : ${CFLAGS}
    C++ compiler flags .............. : ${CXXFLAGS}
    Linker flags .................... : ${LDFLAGS}
    Extra libraries ................. : ${LIBS}

EOF

# End of configure.ac
