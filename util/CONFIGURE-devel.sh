#!/bin/bash

export NETIFYD_PREFIX=/tmp/netify-agent

# CentOS 7x
 export PKG_CONFIG_PATH=${NETIFYD_PREFIX}/usr/lib/pkgconfig:/usr/lib/pkgconfig
# Ubuntu 20x
#export PKG_CONFIG_PATH=${NETIFYD_PREFIX}/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig

export CPPFLAGS=$(pkg-config --define-variable=includedir=${NETIFYD_PREFIX}/usr/include --define-variable=libdir=${NETIFYD_PREFIX}/usr/lib64 libnetifyd --cflags)
export LDFLAGS=$(pkg-config --define-variable=includedir=${NETIFYD_PREFIX}/usr/include --define-variable=libdir=${NETIFYD_PREFIX}/usr/lib64 libnetifyd --libs-only-L)

# CentOS 7x
./configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix= --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib64 --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info build_alias=x86_64-redhat-linux-gnu host_alias=x86_64-redhat-linux-gnu
# Ubuntu 20x
#./configure --build=x86_64-linux-gnu --prefix=/usr --includedir=/usr/include --mandir=/usr/share/man --infodir=/usr/share/info --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib/x86_64-linux-gnu --libexecdir=/usr/lib/x86_64-linux-gnu
