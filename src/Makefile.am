AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I ../m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include $(LIBNETIFYD_CFLAGS)

lib_LTLIBRARIES = libnetify-proc-legacy.la

libnetify_proc_legacy_la_SOURCES = npp-plugin.cpp
libnetify_proc_legacy_la_LIBADD = $(LIBNETIFYD_LIBS)
