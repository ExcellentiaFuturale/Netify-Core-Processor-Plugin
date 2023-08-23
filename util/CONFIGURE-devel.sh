#!/bin/bash

: ${COMPILER:=gcc}
: ${VARIANT:=generic}
: ${NETIFYD_PREFIX:=/tmp/netify-agent}
: ${ENABLE_ADDRESS_SANITIZER:=false}
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

if [ "x${ENABLE_ADDRESS_SANITIZER}" == "xtrue" ]; then
  if [ "x${COMPILER}" == "xgcc" ]; then
    echo "Overriding COMPILER to clang, address sanitzer enabled."
    COMPILER=clang
    export LDFLAGS=-fsanitize=address
  fi
fi

echo "Options:"
echo " COMPILER: ${COMPILER}"
echo " VARIANT: ${VARIANT}"
echo " NETIFYD_PREFIX: ${NETIFYD_PREFIX}"
echo " ENABLE_ADDRESS_SANITIZER: ${ENABLE_ADDRESS_SANITIZER}"
echo " ENABLE_STACK_PROTECTION: ${ENABLE_STACK_PROTECTION}"

if [ $# -gt 0 -a "x$1" == "xhelp" ]; then exit 0; fi

CPPFLAGS_COMMON="-pipe -g -O1 -fexceptions -Wall"

if [ "x${COMPILER}" == "xgcc" ]; then
  export CC=gcc
  export CXX=g++
  CPPFLAGS_COMMON="${CPPFLAGS_COMMON} -grecord-gcc-switches"
elif [ "x${COMPILER}" == "xclang" ]; then
  export CC=clang
  export CXX=clang++
  CPPFLAGS_COMMON="${CPPFLAGS_COMMON} -fsanitize=address -fno-omit-frame-pointer"
else
  echo "ERROR: Unsupported COMPILER: ${COMPILER}"
  exit 1
fi

if [ "x${ENABLE_STACK_PROTECTION}" == "xtrue" ]; then
  CPPFLAGS_COMMON="${CPPFLAGS_COMMON} -fstack-clash-protection \
    -fstack-protector-strong -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2"
fi

export PKG_CONFIG_PATH="${NETIFYD_PREFIX}${libdir}/pkgconfig"

export CPPFLAGS="${CPPFLAGS_COMMON} $(pkg-config --define-variable=includedir=${NETIFYD_PREFIX}${includedir} libnetifyd --cflags)"

export LDFLAGS="${LDFLAGS} $(pkg-config --define-variable=libdir=${NETIFYD_PREFIX}${libdir} libnetifyd --libs-only-L)"

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
