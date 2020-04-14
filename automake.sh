#!/bin/bash

automake_gen()
{
    echo "aclocal..."
    aclocal
    echo "autoheader..."
    autoheader
    echo "autoconf..."
    autoconf
    echo "libtoolize..."
    libtoolize --automake --copy --force
    echo "automake..."
    automake --foreign --add-missing --copy
}

automake_clean()
{
    echo "cleaning..."
    rm -rf \
configure \
config.log \
depcomp \
config.status \
config.guess \
config.sub \
ltmain.sh \
autom4te.cache \
libtool \
missing \
aclocal.m4 \
install-sh \
m4 \
config.h.in \
config.h.in~ \
stamp-h1 \
config.h \
makefile.in \
.deps \
makefile
}

automake_distclean()
{
    echo "dist cleaning..."
    rm -rf \
config.log \
config.status \
stamp-h1 \
config.h \
libtool \
.deps \
makefile
}

case "${1}" in
    gen)
        automake_gen
    ;;
    clean)
        automake_clean
    ;;
    distclean)
        automake_distclean
    ;;
    regen)
        automake_clean
        automake_gen
    ;;
    *)
        echo "Usage: ${0} gen|clean|distclean"
    ;;
esac

# End of automake.sh
