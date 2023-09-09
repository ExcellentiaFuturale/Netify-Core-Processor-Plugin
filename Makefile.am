DEBUG_HOST = root@gw.qw.sokoloski.ca

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = src deploy

EXTRA_DIST = autogen.sh include

include $(abs_top_srcdir)/automake/dist-git.am
include $(abs_top_srcdir)/automake/deploy-rpm.am
include $(abs_top_srcdir)/automake/deploy-debug.am
