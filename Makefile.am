AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter

noinst_LIBRARIES = libcore.a
bin_PROGRAMS = peterad petera

libcore_a_CFLAGS = @OPENSSL_CFLAGS@
libcore_a_SOURCES = \
	src/asn1.c \
	src/asn1.h \
	src/cleanup.c \
	src/cleanup.h \
	src/d2i.c \
	src/d2i.h \
	src/main.c \
	src/common.h

peterad_CFLAGS = @OPENSSL_CFLAGS@ @LIBSYSTEMD_CFLAGS@
peterad_LDADD = @OPENSSL_LIBS@ @LIBSYSTEMD_LIBS@ libcore.a
peterad_SOURCES = \
	src/peterad/ctx.c \
	src/peterad/ctx.h \
	src/peterad/decrypt.c \
	src/peterad/decrypt.h \
	src/peterad/run.c

petera_CFLAGS = @OPENSSL_CFLAGS@ @CRYPTSETUP_CFLAGS@
petera_LDADD = @OPENSSL_LIBS@ @CRYPTSETUP_LIBS@ libcore.a
petera_SOURCES = \
	src/petera/cryptsetup/main.c \
	src/petera/askpass/askp.c \
	src/petera/askpass/askp.h \
	src/petera/askpass/iface.c \
	src/petera/askpass/iface.h \
	src/petera/askpass/list.c \
	src/petera/askpass/list.h \
	src/petera/askpass/main.c \
	src/petera/askpass/main.h \
	src/petera/query.c \
	src/petera/query.h \
	src/petera/encrypt.c \
	src/petera/encrypt.h \
	src/petera/decrypt.c \
	src/petera/decrypt.h \
	src/petera/run.c

dist_noinst_DATA = peterad.service.in peterad.socket.in
systemdsystemunit_DATA = peterad.socket peterad.service

install-data-local:
	mkdir -p $(DESTDIR)/$(PETERAD_CONF)/decrypt.d
	mkdir -p $(DESTDIR)/$(PETERA_CONF)

@ifGNUmake@ include $(srcdir)/CA.mk