SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

CLEANALL = $(systemdsystemunit_DATA) $(dracut_DATA) $(dracut_SCRIPTS)

EXTRA_DIST = CA.mk

clean-local:
	rm -rf $(CLEANALL)

@ifGNUmake@ include $(srcdir)/CA.mk
