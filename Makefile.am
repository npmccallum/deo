SUBDIRS = src

AM_MAKEFLAGS = --no-print-directory

CLEANALL = $(systemdsystemunit_DATA) $(dracut_DATA) $(dracut_SCRIPTS)

EXTRA_DIST = \
	CA.mk \
	dracut/petera-askpassd.service.in \
	dracut/module-setup.sh.in \
	petera-decryptd.service.in \
	petera-decryptd.socket.in

systemdsystemunit_DATA = petera-decryptd.socket petera-decryptd.service

dracut_DATA = dracut/petera-askpassd.service
dracut_SCRIPTS = dracut/module-setup.sh

%.sh: %.sh.in
	 $(AM_V_GEN)$(SED) \
		-e 's,@PETERA_CONF\@,$(PETERA_CONF),g' \
		-e 's,@PETERA_PLUGINS\@,$(PETERA_PLUGINS),g' \
		$< > $@

%.service: %.service.in
	$(AM_V_GEN)$(SED) \
		-e 's,@bindir\@,$(bindir),g' \
		-e 's,@PETERA_CONF\@,$(PETERA_CONF),g' \
		$< > $@

%.socket: %.socket.in
	$(AM_V_GEN)$(SED) \
		-e 's,@bindir\@,$(bindir),g' \
		-e 's,@PETERA_SOCKET\@,$(PETERA_SOCKET),g' \
		$< > $@

clean-local:
	rm -rf $(CLEANALL)

@ifGNUmake@ include $(srcdir)/CA.mk
