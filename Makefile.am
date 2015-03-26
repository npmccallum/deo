AM_LDFLAGS = @OPENSSL_LIBS@ @LIBSYSTEMD_LIBS@
AM_CFLAGS = @OPENSSL_CFLAGS@ @LIBSYSTEMD_CFLAGS@ \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter

bin_PROGRAMS = peterad petera
CORE = src/cleanup.c src/cleanup.h
OPENSSL = $(CORE) \
	src/asn1.c \
	src/asn1.h \
	src/cleanup_openssl.c \
	src/cleanup_openssl.h \
	src/d2i.c \
	src/d2i.h \
	src/main.c \
	src/common.h

peterad_SOURCES = $(OPENSSL) \
	src/s_ctx.c \
	src/s_ctx.h \
	src/s_decrypt.c \
	src/s_decrypt.h \
	src/s_run.c

petera_SOURCES = $(OPENSSL) \
	src/c_common.c \
	src/c_common.h \
	src/c_query.c \
	src/c_encrypt.c \
	src/c_decrypt.c \
	src/c_retarget.c \
	src/c_targets.c \
	src/c_run.c

dist_noinst_DATA = peterad.service.in
systemdsystemunit_DATA = peterad.socket peterad.service

install-data-local:
	mkdir -p $(DESTDIR)/$(psysconfdir)/decrypt.d
	touch $(DESTDIR)/$(psysconfdir)/$(PACKAGE_NAME)d.pem
	touch $(DESTDIR)/$(psysconfdir)/encrypt.pem

@ifGNUmake@ include $(srcdir)/CA.mk