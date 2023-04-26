DEBUG_HOST = root@gw.qw.sokoloski.ca

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = src deploy

EXTRA_DIST = autogen.sh include

deploy-debug: all
	rsync -avl --progress --inplace src/.libs/libnetify*.so* $(DEBUG_HOST):/usr/lib64/

deploy-rpm:
	$(MAKE) dist-gzip
	cp -v $(PACKAGE)-$(VERSION).tar.gz ~/rpmbuild/SOURCES/
	rpmbuild -ba $(PACKAGE).spec
