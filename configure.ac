# Netify Agent Core Processor Plugin

AC_PREREQ([2.69])
AC_INIT([Netify Core Processor Plugin], [1.0.20],
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
NETIFY_MINVER=4.5.24
AC_SUBST([NETIFY_MINVER], [$NETIFY_MINVER])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT
PKG_PROG_PKG_CONFIG([0.23])
AX_PKG_INSTALLDIR

BUILD_UUID=00000000-0000-0000-0000-000000000000

AC_PATH_PROG([uuidgen], [uuidgen], [false])
AS_IF([test "x$ac_cv_path_uuidgen" != "xfalse"], [
  BUILD_UUID=`${ac_cv_path_uuidgen}`
], [
  AC_PATH_PROG([uuid], [uuid], [false])
  AS_IF([test "x$ac_cv_path_uuid" != "xfalse"], [
    BUILD_UUID=`${ac_cv_path_uuid}`
  ])
])

AC_DEFINE_UNQUOTED(NPP_BUILD_UUID, "${BUILD_UUID}", [Build UUID])

# Check compiler flags (gnu++11)
AX_CXX_COMPILE_STDCXX_11
AS_VAR_APPEND([CXXFLAGS], [" -std=gnu++11"])

# Checks for packages
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([LIBNETIFYD], [libnetifyd >= $NETIFY_MINVER],
    [ac_persistentstatedir=`$PKG_CONFIG --variable=persistentstatedir libnetifyd`;\
     ac_volatilestatedir=`$PKG_CONFIG --variable=volatilestatedir libnetifyd`],
    [AC_MSG_ERROR([Netify Agent pkg-config not found])]
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
    GIT_DATE_UNIX=`git log -1 --format=%ct`

    GIT_LAST_COMMIT_HASH=`git log -1 --format=%H`
    case "${host_os}" in
        linux*)
            GIT_LAST_COMMIT_DATE=`date -d "@${GIT_DATE_UNIX}" '+%F'`
        ;;
    *)
            GIT_LAST_COMMIT_DATE=`date -r "${GIT_DATE_UNIX}" '+%F'`
        ;;
    esac

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
AC_SUBST([GIT_SOURCE_URL], [https://gitlab.com/netify.ai/public/netify-plugins/netify-proc-core.git])

# Output files
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([deploy/Makefile deploy/plugins.d/Makefile deploy/openwrt/Makefile deploy/debian/Makefile deploy/rpm/Makefile])

AC_OUTPUT

AS_BOX([${PACKAGE_NAME} v${PACKAGE_VERSION}])
AC_MSG_NOTICE([Build UUID: ${BUILD_UUID}])
