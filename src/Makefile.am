AM_CFLAGS = $(PTHREAD_CFLAGS)

lib_LTLIBRARIES = libpagecache.la

libpagecache_la_SOURCES = \
	pagecache.c

libpagecache_la_LIBADD = @LIBDLSYM_LIBS@ @PTHREAD_LIBS@
