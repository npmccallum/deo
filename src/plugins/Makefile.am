AM_LDFLAGS = -module -avoid-version -export-symbols-regex ^deo$
AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-Wno-sign-compare

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
	askpassd/question.c \
	askpassd/question.h \
	askpassd/askp.c \
	askpassd/askp.h \
	askpassd/iface.c \
	askpassd/iface.h \
	askpassd/list.c \
	askpassd/list.h \
	askpassd/main.c

install-data-hook:
	$(MKDIR_P) $(DESTDIR)/$(DEO_CONF)/decrypt.d
	$(MKDIR_P) $(DESTDIR)/$(DEO_CONF)/disks.d
	touch $(DESTDIR)/$(DEO_CONF)/decryptd.pem
	touch $(DESTDIR)/$(DEO_CONF)/encrypt.pem
	rm -f $(DESTDIR)/$(plugindir)/*.la

CLEANFILES = $(systemdsystemunit_DATA) $(dracut_SCRIPTS)
EXTRA_DIST = \
	decryptd/deo-decryptd.service.in \
	decryptd/deo-decryptd.socket.in \
	askpassd/deo-askpassd.path.in \
	askpassd/deo-askpassd.service.in \
	askpassd/module-setup.sh.in

dracut_SCRIPTS = askpassd/module-setup.sh
systemdsystemunit_DATA = \
	decryptd/deo-decryptd.socket \
	decryptd/deo-decryptd.service \
	askpassd/deo-askpassd.path \
	askpassd/deo-askpassd.service

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@bindir\@,$(bindir),g' \
		-e 's,@DEO_CONF\@,$(DEO_CONF),g' \
		-e 's,@DEO_SOCKET\@,$(DEO_SOCKET),g' \
		-e 's,@DEO_PLUGINS\@,$(DEO_PLUGINS),g' \
		$(srcdir)/$@.in > $@
