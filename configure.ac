AC_PREREQ(2.59)
AC_INIT(petera, 0.1)
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC_C99

AM_INIT_AUTOMAKE([subdir-objects foreign std-options])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])
LT_SYS_MODULE_EXT

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([CRYPTSETUP], [libcryptsetup])
PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd], [], [AC_MSG_ERROR([libsystemd/systemd-devel not found])])

PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
            [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])


AC_SUBST([PETERA_SOCKET], [5700])
AC_SUBST([PETERA_CONF], [${sysconfdir}/${PACKAGE_NAME}])
AC_SUBST([plugindir], [${libdir}/${PACKAGE_NAME}/plugins])

AX_DEFINE_DIR(PETERA_SOCKET, PETERA_SOCKET, [Default petera socket])
AX_DEFINE_DIR(PETERA_CONF, PETERA_CONF, [Location of petera configuration])
AX_DEFINE_DIR(PETERA_PLUGINS, plugindir, [Location of petera plugins])

AX_CHECK_GNU_MAKE()
AC_CONFIG_FILES(Makefile src/Makefile src/plugins/Makefile)
AC_OUTPUT

