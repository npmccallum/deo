SUBDIRS = src

AM_MAKEFLAGS = --no-print-directory

EXTRA_DIST = CA.mk petera-decryptd.service.in petera-decryptd.socket.in
systemdsystemunit_DATA = \
	petera-decryptd.socket \
	petera-decryptd.service \
	petera-askpassd.service

%.service: %.service.in
	$(AM_V_GEN)sed \
		-e 's,@bindir\@,$(bindir),g' \
		-e 's,@PETERA_CONF\@,$(PETERA_CONF),g' \
		$< > $@

%.socket: %.socket.in
	$(AM_V_GEN)sed \
		-e 's,@bindir\@,$(bindir),g' \
		-e 's,@PETERA_SOCKET\@,$(PETERA_SOCKET),g' \
		$< > $@

clean-local:
	-rm -rf *.service *.socket PCA CCA SVC

@ifGNUmake@ include $(srcdir)/CA.mk