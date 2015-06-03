SUBDIRS = plugins

AM_CFLAGS = \
	-Wall \
	-Wextra \
	-Werror \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-Wno-sign-compare

bin_PROGRAMS = deo
deo_CFLAGS = $(AM_CFLAGS) @OPENSSL_CFLAGS@ -ldl
deo_LDADD = @OPENSSL_LIBS@
deo_LDFLAGS = -rdynamic
deo_SOURCES = \
	asn1.c \
	asn1.h \
	cleanup.c \
	cleanup.h \
	d2i.c \
	d2i.h \
	misc.c \
	misc.h \
	main.c \
	main.h
