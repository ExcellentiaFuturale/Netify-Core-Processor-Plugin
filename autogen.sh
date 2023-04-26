#!/bin/sh -x

# Regenerate configuration files
find $(pwd) -name configure.ac | xargs touch

autoreconf -i --force -I m4 || exit 1

