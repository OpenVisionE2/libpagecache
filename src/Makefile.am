AM_CXXFLAGS = \
	@PTHREAD_CFLAGS@ \
	@LIBPAGECACHE_CXXFLAGS@

AM_CPPFLAGS = @LIBPAGECACHE_CPPFLAGS@

lib_LTLIBRARIES = libpagecache.la

libpagecache_la_SOURCES = \
	pagecache.cpp

libpagecache_la_LDFLAGS = -avoid-version -module -shared

libpagecache_la_LIBADD = @LIBDLSYM_LIBS@ @PTHREAD_LIBS@
