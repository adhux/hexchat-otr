ACLOCAL_AMFLAGS = -I m4

hexchatlib_LTLIBRARIES = otr.la
otr_la_SOURCES = \
	src/otr_key.c \
	src/otr_ops.c \
	src/otr_util.c \
	src/hexchat_otr.c \
	src/hexchat-formats.c

otr_la_CFLAGS = $(OTR_CFLAGS) $(GLIB_CFLAGS) $(GCRYPT_CFLAGS)
otr_la_LIBADD = $(OTR_LIBS) $(GLIB_LIBS) $(GCRYPT_LIBS)
otr_la_LDFLAGS = -avoid-version -module -export-symbols-regex hexchat_.*

noinst_HEADERS = \
	src/otr.h \
	src/otr-formats.h \
	src/hexchat_otr.h

src/otr-formats.h src/hexchat-formats.c: src/formats.txt src/makeformats.py
	$(AM_V_GEN) python src/makeformats.py $< src

BUILT_SOURCES = src/otr-formats.h src/hexchat-formats.c

EXTRA_DIST = $(BUILT_SOURCES) autogen.sh LICENSE src/formats.txt src/makeformats.py
