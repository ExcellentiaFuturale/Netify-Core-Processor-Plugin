# Netify Agent Default Plugins Configuration Automake File
# Copyright (C) 2023 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

TEMPLATEFILES = 10-$(PACKAGE_TARNAME).conf
TEMPLATEFILES_IN = 10-$(PACKAGE_TARNAME).in

pluginsdir = $(persistentstatedir)/plugins.d
plugins_DATA = $(TEMPLATEFILES)

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)
EXTRA_DIST = $(TEMPLATEFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]libdir@|$(libdir)|g' \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]persistentstatedir@|$(persistentstatedir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"
