AM_CFLAGS = $(PTHREAD_CFLAGS)

lib_LTLIBRARIES = libpagecache.la

libpagecache_la_SOURCES = \
	pagecache.c \
	symbol.c \
	symbol.h

libpagecache_la_LIBADD = @PTHREAD_LIBS@
