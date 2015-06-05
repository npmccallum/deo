AC_PREREQ(2.59)
AC_INIT(deo, 0.4.1)
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC_C99
AC_PROG_MKDIR_P
AC_PROG_SED

AM_INIT_AUTOMAKE([subdir-objects foreign std-options])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])
LT_SYS_MODULE_EXT

AC_CHECK_FILE([/usr/lib/dracut/modules.d],
              [AC_SUBST([dracutdir], [/usr/lib/dracut/modules.d/60deo])],
              [AC_MSG_ERROR(not found)])

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([CRYPTSETUP], [libcryptsetup])
PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd], [], [PKG_CHECK_MODULES([LIBSYSTEMD], [systemd], [], AC_MSG_ERROR([libsystemd/systemd-devel not found]))])

PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
AC_ARG_WITH([systemdsystemunitdir],
            AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
            [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])


AC_SUBST([DEO_SOCKET], [5700])
AC_SUBST([DEO_CONF], [${sysconfdir}/${PACKAGE_NAME}])
AC_SUBST([plugindir], [${libdir}/${PACKAGE_NAME}/plugins])

AX_DEFINE_DIR(DEO_SOCKET, DEO_SOCKET, [Default deo socket])
AX_DEFINE_DIR(DEO_CONF, DEO_CONF, [Location of deo configuration])
AX_DEFINE_DIR(DEO_PLUGINS, plugindir, [Location of deo plugins])

AX_CHECK_GNU_MAKE()
AC_CONFIG_FILES(Makefile src/Makefile src/plugins/Makefile)
AC_OUTPUT

