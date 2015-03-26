AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter

noinst_LIBRARIES = libcore.a libopenssl.a
bin_PROGRAMS = peterad petera

libcore_a_SOURCES = src/cleanup.c src/cleanup.h

libopenssl_a_CFLAGS = @OPENSSL_CFLAGS@
libopenssl_a_SOURCES = \
	src/asn1.c \
	src/asn1.h \
	src/cleanup_openssl.c \
	src/cleanup_openssl.h \
	src/d2i.c \
	src/d2i.h \
	src/main.c \
	src/common.h

peterad_CFLAGS = @OPENSSL_CFLAGS@ @LIBSYSTEMD_CFLAGS@
peterad_LDADD = @OPENSSL_LIBS@ @LIBSYSTEMD_LIBS@ libcore.a libopenssl.a
peterad_SOURCES = \
	src/s_ctx.c \
	src/s_ctx.h \
	src/s_decrypt.c \
	src/s_decrypt.h \
	src/s_run.c

petera_CFLAGS = @OPENSSL_CFLAGS@
petera_LDADD = @OPENSSL_LIBS@ libcore.a libopenssl.a
petera_SOURCES = \
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