AC_PREREQ([2.69])
AC_INIT([hexchat-otr], [0.1.0])
AC_CONFIG_SRCDIR([src/otr.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_INSTALL
AC_PATH_PROG([GCRYPT_CONFIG], [libgcrypt-config], [no])

AM_INIT_AUTOMAKE([1.11 silent-rules tar-pax dist-xz no-dist-gzip subdir-objects no-define foreign -Wall])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_INIT

PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([OTR], [libotr >= 4.0.0])

AC_MSG_CHECKING([for GCRYPT])
if test "$GCRYPT_CONFIG" = "no"; then
	AC_MSG_ERROR([no])
else
	GCRYPT_CFLAGS="`$GCRYPT_CONFIG --cflags`"
	GCRYPT_LIBS="`$GCRYPT_CONFIG --libs`"
	AC_SUBST([GCRYPT_CFLAGS])
	AC_SUBST([GCRYPT_LIBS])
	AC_MSG_RESULT([yes])
fi

AC_MSG_CHECKING([for hexchat's plugin path])
if $PKG_CONFIG hexchat-plugin --exists; then
	hexchatlibdir="`$PKG_CONFIG --variable=hexchatlibdir hexchat-plugin`"
	AC_MSG_RESULT([$hexchatlibdir])
else
	hexchatlibdir="$libdir/hexchat/plugins"
	AC_MSG_RESULT([not found, assuming $hexchatlibdir])
fi
AC_SUBST([hexchatlibdir])

CFLAGS="$CFLAGS"
# TODO: Improve
if test "$CC" = "gcc" || test "$CC" = "clang"; then
	CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers"
fi
AC_SUBST([CFLAGS])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT
echo "
    $PACKAGE $VERSION

    install location: ${hexchatlibdir}
"
