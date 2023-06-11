# Netify Agent Legacy Processor Plugin

AC_PREREQ([2.69])
AC_INIT([Netify Legacy Processor Plugin], [1.0.7],
    [https://gitlab.com/netify.ai/public/netify-plugins/netify-proc-legacy/issues],
    [netify-proc-legacy],[http://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([src/npp-plugin.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

# Set the minimum Agent version this plugin requires.
# When updating this version, remember to update .gitlab-ci.yml too.
NETIFY_MINVER=4.5.15
AC_SUBST([NETIFY_MINVER], [$NETIFY_MINVER])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT
PKG_PROG_PKG_CONFIG([0.23])
AX_PKG_INSTALLDIR

# Check compiler flags (gnu++11)
AX_CXX_COMPILE_STDCXX_11([ext], [optional])
AS_IF([test "$HAVE_CXX11" = "0"], [AX_CXX_COMPILE_STDCXX_0X])

# Checks for packages
PKG_CHECK_MODULES([LIBNETIFYD], [libnetifyd >= $NETIFY_MINVER],
    [ac_persistentstatedir=`$PKG_CONFIG --variable=persistentstatedir libnetifyd`;\
     ac_volatilestatedir=`$PKG_CONFIG --variable=volatilestatedir libnetifyd`],
    [ac_persistentstatedir=;ac_volatilestatedir=;]
)

AS_IF([test "x$ac_persistentstatedir" = "x"],
    AC_MSG_ERROR([couldn't determine Netify Agent's persistent state directory]),
    AC_SUBST(persistentstatedir, $ac_persistentstatedir)
)

AS_IF([test "x$ac_volatilestatedir" = "x"],
    AC_MSG_ERROR([couldn't determine Netify Agent's volatile state directory]),
    AC_SUBST(volatilestatedir, $ac_volatilestatedir)
)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for libraries.

# Checks for library functions.

# Get git revision
if test -e ".git"; then :
    GIT_TAG=`git log -1 --format=%h`
    GIT_DATE=`git log -1 --format=%cd`
    GIT_DATE_ISO8601=`git log -1 --format=%ci`

    GIT_LAST_COMMIT_HASH=`git log -1 --format=%H`
    GIT_LAST_COMMIT_DATE=`date -d "${GIT_DATE_ISO8601}" '+%F'`

    AC_SUBST([GIT_LAST_COMMIT_HASH], [$GIT_LAST_COMMIT_HASH])
    AC_SUBST([GIT_LAST_COMMIT_DATE], [$GIT_LAST_COMMIT_DATE])

    # On CentOS 6 `git rev-list HEAD --count` does not work
    GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
    GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
    GIT_RELEASE="${PACKAGE_VERSION}-${GIT_BRANCH}-${GIT_NUM}-${GIT_TAG}"
else
    GIT_RELEASE="${PACKAGE_VERSION}"
    GIT_DATE=`date`
fi

AC_DEFINE_UNQUOTED(GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(GIT_DATE, "${GIT_DATE}", [Last GIT change])
AC_SUBST([GIT_SOURCE_URL], [git@gitlab.com:netify.ai/public/netify-plugins/netify-proc-legacy.git])

# Output files
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([deploy/Makefile deploy/plugins.d/Makefile deploy/openwrt/Makefile deploy/debian/Makefile deploy/rpm/Makefile])

AC_OUTPUT
