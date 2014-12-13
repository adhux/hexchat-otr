
libdir = $(hexchatlibdir)

lib_LTLIBRARIES = otr.la
otr_la_SOURCES = otr_key.c otr_ops.c otr_util.c hexchat_otr.c hexchat-formats.c
otr_la_CFLAGS = $(OTR_CFLAGS) $(GLIB_CFLAGS) $(GCRYPT_CFLAGS)
otr_la_LIBADD = $(OTR_LIBS) $(GLIB_LIBS) $(GCRYPT_LIBS)
otr_la_LDFLAGS = -avoid-version -module

EXTRA_DIST = formats.txt makeformats.py otr.h otr-formats.h hexchat_otr.h

