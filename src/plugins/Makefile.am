AM_LDFLAGS = -module -avoid-version -export-symbols-regex ^petera$
AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter

plugin_LTLIBRARIES = \
	askpassd.la \
	cryptsetup.la \
	decrypt.la \
	decryptd.la \
	encrypt.la \
	query.la \
	targets.la

cryptsetup_la_CFLAGS = $(AM_CFLAGS) @CRYPTSETUP_CFLAGS@
cryptsetup_la_LIBADD = @CRYPTSETUP_LIBS@

decryptd_la_CFLAGS = $(AM_CFLAGS) @LIBSYSTEMD_CFLAGS@
decryptd_la_LIBADD = @LIBSYSTEMD_LIBS@
decryptd_la_SOURCES = \
	decryptd/ctx.c \
	decryptd/ctx.h \
	decryptd/decrypt.c \
	decryptd/decrypt.h \
	decryptd/main.c

askpassd_la_SOURCES = \
	askpassd/askp.c \
	askpassd/askp.h \
	askpassd/iface.c \
	askpassd/iface.h \
	askpassd/list.c \
	askpassd/list.h \
	askpassd/main.c \
	askpassd/main.h

install-data-hook:
	$(MKDIR_P) $(DESTDIR)/$(PETERA_CONF)/decrypt.d
	$(MKDIR_P) $(DESTDIR)/$(PETERA_CONF)/disks.d
	rm -f $(DESTDIR)/$(plugindir)/*.la