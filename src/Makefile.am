AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I ../m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE \
	-I ../include $(LIBNETIFYD_CFLAGS) $(LIBCURL_CFLAGS)

lib_LTLIBRARIES = libnetify-proc-core.la

libnetify_proc_core_la_SOURCES = npp-plugin.cpp
libnetify_proc_core_la_LIBADD = $(LIBNETIFYD_LIBS)
