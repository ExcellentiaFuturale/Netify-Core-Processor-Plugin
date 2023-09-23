# Netify Agent Core Processor Plugin

m4_include([m4/ax_pkg_installdir.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
m4_include([m4/ax_git_vars.m4])
m4_include([m4/ax_check_progs.m4])

AC_PREREQ([2.69])
AC_INIT([Netify Core Processor Plugin], [1.0.21],
    [https://gitlab.com/netify.ai/public/netify-plugins/netify-proc-core/issues],
    [netify-proc-core],[http://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([src/npp-plugin.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

# Set the minimum Agent version this plugin requires.
# When updating this version, remember to update .gitlab-ci.yml too.
NETIFY_MINVER=5.0.1
AC_SUBST([NETIFY_MINVER], [$NETIFY_MINVER])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT
PKG_PROG_PKG_CONFIG([0.23])
AX_PKG_INSTALLDIR
AX_CHECK_PROGS

# Generate a random build UUID
AX_BUILD_UUID
AC_DEFINE_UNQUOTED(NPP_BUILD_UUID, "${BUILD_UUID}", [Build UUID])

# Check compiler flags (gnu++11)
AX_CXX_COMPILE_STDCXX_11
AS_VAR_APPEND([CXXFLAGS], [" -std=gnu++11"])

# Checks for packages.
PKG_CHECK_MODULES([LIBCURL], [libcurl])
AX_CHECK_NETIFYD

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for libraries.

# Checks for library functions.

# Get git revision
AX_GIT_VARS
AC_SUBST([GIT_SOURCE_URL], [https://gitlab.com/netify.ai/public/netify-plugins/netify-proc-core.git])

# Output files
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([deploy/Makefile \
		 deploy/plugins.d/Makefile deploy/openwrt/Makefile \
		 deploy/debian/Makefile deploy/rpm/Makefile \
		 deploy/freebsd/Makefile deploy/freebsd/pkg-plist])
AC_OUTPUT

AS_BOX([${PACKAGE_NAME} v${PACKAGE_VERSION}])
AC_MSG_NOTICE([Build UUID: ${BUILD_UUID}])
