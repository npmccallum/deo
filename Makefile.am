SUBDIRS = src

ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory

CLEANALL = $(systemdsystemunit_DATA) $(dracut_DATA) $(dracut_SCRIPTS)

clean-local:
	rm -rf $(CLEANALL)

EXTRA_DIST = README.md tests/test.py tests/ca.py tests/server.py

AM_TESTS_ENVIRONMENT = export DEO_PLUGINS=src/plugins/.libs DEO_BIN=src/deo;
TESTS = tests/test.py
