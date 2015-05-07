AC_PREREQ(2.59)
AC_INIT(petera, 0.1)
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC_C99
AC_PROG_RANLIB

AM_INIT_AUTOMAKE([subdir-objects foreign])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([OPENSSL], [openssl])

PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd], [], [AC_MSG_ERROR([libsystemd/systemd-devel not found])])
PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
            [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])

AC_SUBST([psysconfdir], [${sysconfdir}/${PACKAGE_NAME}])
PETERAD_BINARY=${bindir}/${PACKAGE_NAME}d${EXEEXT}
PETERA_CONF=${psysconfdir}
AX_DEFINE_DIR(PETERAD_BINARY, PETERAD_BINARY, [Location of peterad binary])
AX_DEFINE_DIR(PETERA_CONF, PETERA_CONF, [Location of petera server configuration])

AX_CHECK_GNU_MAKE()
AC_CONFIG_FILES(Makefile peterad.service)
AC_OUTPUT

