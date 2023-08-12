# Netify Core Processor RPM Automake File
# Copyright (C) 2023 eGloo Incorporated

RPMFILES = $(PACKAGE_TARNAME).spec
RPMFILES_IN = $(PACKAGE_TARNAME).spec.in

BUILT_SOURCES = $(RPMFILES)
CLEANFILES = $(RPMFILES)
EXTRA_DIST = $(RPMFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]PACKAGE_BUGREPORT@|$(PACKAGE_BUGREPORT)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]NETIFY_MINVER@|$(NETIFY_MINVER)|g' \
		< "$<" > "$@"
