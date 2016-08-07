AC_PREREQ([2.69])
AC_INIT([hexchat-otr], [0.2.1])
AC_CONFIG_SRCDIR([src/otr.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PATH_PROG([GCRYPT_CONFIG], [libgcrypt-config], [no])

AM_INIT_AUTOMAKE([1.11 silent-rules tar-pax dist-xz no-dist-gzip subdir-objects no-define foreign -Wall])
AM_SILENT_RULES([yes])
AM_PROG_AR

AC_DEFUN([HOTR_CHECK_MACRO], [m4_ifndef([$1], [m4_fatal([macro ]$1[ is not defined. Is ]$2[ installed?])])])
HOTR_CHECK_MACRO([AX_APPEND_COMPILE_FLAGS], [autoconf-archive])

LT_PREREQ([2.2.0])
LT_INIT

PKG_PROG_PKG_CONFIG([0.28])
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([OTR], [libotr >= 4.0.0])

AC_MSG_CHECKING([for GCRYPT])
AS_IF([test "$GCRYPT_CONFIG" = "no"], [
	AC_MSG_ERROR([no])
], [
	GCRYPT_CFLAGS="`$GCRYPT_CONFIG --cflags`"
	GCRYPT_LIBS="`$GCRYPT_CONFIG --libs`"
	AC_SUBST([GCRYPT_CFLAGS])
	AC_SUBST([GCRYPT_LIBS])
	AC_MSG_RESULT([yes])
])

AC_MSG_CHECKING([for hexchat's plugin path])
AS_IF([$PKG_CONFIG hexchat-plugin --exists], [
	hexchatlibdir="`$PKG_CONFIG --variable=hexchatlibdir hexchat-plugin`"
	AC_MSG_RESULT([$hexchatlibdir])
], [
	hexchatlibdir="$libdir/hexchat/plugins"
	AC_MSG_RESULT([not found, assuming $hexchatlibdir])
])
AC_SUBST([hexchatlibdir])

AX_APPEND_COMPILE_FLAGS([ \
	-std=gnu99 \
	-funsigned-char \
	-fstack-protector-strong \
	-fPIE \
	-fPIC \
	-Wall \
	-Wextra \
	-Wconversion \
	-Winline \
	-Wno-padded \
	-Wno-unused-parameter \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Werror=implicit-function-declaration \
	-Werror=pointer-arith \
	-Werror=init-self \
	-Werror=format=2 \
	-Werror=missing-include-dirs \
	-Werror=date-time \
])

AC_CONFIG_FILES([
    Makefile
])

AC_OUTPUT
echo "
    $PACKAGE $VERSION

    install location: ${hexchatlibdir}
"
