#!/usr/bin/env bash

# Example FreeBSD invocation:
#   COMPILER=clang prefix=/usr/local libdir=/usr/local/lib sysconfdir=/usr/local/etc ./util/CONFIGURE-devel.sh

: ${COMPILER:=gcc}
: ${CPPFLAGS:="-pipe -g -O1 -fexceptions -Wall"}
: ${LDFLAGS:=}
: ${VARIANT:=generic}
: ${NETIFYD_PREFIX:=/tmp/netify-agent}
: ${ENABLE_SANITIZER:=false}
: ${ENABLE_STACK_PROTECTION:=false}

: ${prefix:=/usr}
: ${exec_prefix:=${prefix}}
: ${bindir:=${prefix}/bin}
: ${sbindir:=${prefix}/sbin}
: ${sysconfdir:=/etc}
: ${datadir:=${prefix}/share}
: ${includedir:=${prefix}/include}
: ${libdir:=${prefix}/lib64}
: ${libexecdir:=${prefix}/libexec}
: ${localstatedir:=/var}
: ${sharedstatedir:=/var/lib}
: ${mandir:=${prefix}/share/man}
: ${infodir:=${prefix}/share/info}

export PKG_CONFIG_PATH="${NETIFYD_PREFIX}${libdir}/pkgconfig"

if [ "x${ENABLE_SANITIZER}" == "xtrue" ]; then
  if [ "x${COMPILER}" == "xgcc" ]; then
    echo "Overriding COMPILER to clang, sanitizer enabled."
    COMPILER=clang
  fi
fi

if [ "x${COMPILER}" == "xgcc" ]; then
  export CC=gcc
  export CXX=g++
  CPPFLAGS+=" -grecord-gcc-switches"
elif [ "x${COMPILER}" == "xclang" ]; then
  export CC=clang
  export CXX=clang++

  if [ "x${ENABLE_SANITIZER}" != "xfalse" ]; then
    CPPFLAGS+=" -fsanitize=${ENABLE_SANITIZER} -fno-omit-frame-pointer"
    LDFLAGS+=" -fsanitize=${ENABLE_SANITIZER}"
  fi
else
  echo "ERROR: Unsupported COMPILER: ${COMPILER}"
  exit 1
fi

if [ "x${ENABLE_STACK_PROTECTION}" == "xtrue" ]; then
  CPPFLAGS+=" -fstack-clash-protection \
    -fstack-protector-strong -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2"
fi

export CPPFLAGS+=" $(pkg-config --define-variable=includedir=${NETIFYD_PREFIX}${includedir} libnetifyd --cflags)"
export LDFLAGS+=" $(pkg-config --define-variable=libdir=${NETIFYD_PREFIX}${libdir} libnetifyd --libs-only-L)"

case "x${VARIANT}" in
xgeneric)
  ;;
xcentos7x)
  ;;
xubuntu20x)
  ;;
*)
  echo "ERROR: Unsupported VARIANT: ${VARIANT}"
  exit 1
  ;;
esac

echo "Options:"
echo " COMPILER: ${COMPILER}"
echo " CPPFLAGS: ${CPPFLAGS}"
echo " LDFLAGS: ${LDFLAGS}"
echo " VARIANT: ${VARIANT}"
echo " NETIFYD_PREFIX: ${NETIFYD_PREFIX}"
echo " ENABLE_SANITIZER: ${ENABLE_SANITIZER}"
echo " ENABLE_STACK_PROTECTION: ${ENABLE_STACK_PROTECTION}"

if [ $# -gt 0 -a "x$1" == "xhelp" ]; then exit 0; fi

./configure \
    --program-prefix= \
    --prefix=${prefix} \
    --exec-prefix=${exec_prefix} \
    --bindir=${bindir} \
    --sbindir=${sbindir} \
    --sysconfdir=${sysconfdir} \
    --datadir=${datadir} \
    --includedir=${includedir} \
    --libdir=${libdir} \
    --libexecdir=${libexecdir} \
    --localstatedir=${localstatedir} \
    --sharedstatedir=${sharedstatedir} \
    --mandir=${mandir} \
    --infodir=${infodir} \
    $@ || exit $?

cat << EOF > compile_flags.txt
-std=gnu++11
-DHAVE_CONFIG_H
-I./
-I../include/
-I./include/
-I${NETIFYD_PREFIX}${includedir}/ndpi/
-I${NETIFYD_PREFIX}${includedir}/netifyd/
EOF

exit 0
