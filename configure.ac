#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([libpagecache], [0.0.2], [enigma2-devel@lists.elitedvb.net])
AM_INIT_AUTOMAKE([dist-bzip2 foreign no-define tar-pax -Wno-portability])
AC_CONFIG_SRCDIR([src/pagecache.cpp])
AC_CONFIG_HEADERS([libpagecache-config.h])

# Silent rules are available since 1.11, but older versions
# are still in use. So don't use them unconditionally.
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_USE_SYSTEM_EXTENSIONS

m4_ifdef([LT_INIT], [LT_INIT], [AC_PROG_LIBTOOL])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

AX_CXX_COMPILE_STDCXX_0X

# Checks for libraries.
AX_PTHREAD

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h])
PKG_CHECK_MODULES(LIBDLSYM, [libdlsym])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 memset pipe2 strtoul])

AX_CHECK_COMPILE_FLAG([-Wno-error=cpp],[w_no_error_cpp="yes"],[w_no_error_cpp="no"])
if test "$w_no_error_cpp" = "yes"; then
	LIBPAGECACHE_CPPFLAGS="-Werror -Wno-error=cpp"
else
	# older gcc/mipsel (e.g. 4.4.5)
	LIBPAGECACHE_CPPFLAGS="-Wno-strict-aliasing"
fi

if test "$ax_cv_cxx_compile_cxx0x_gxx" = "yes"; then
LIBPAGECACHE_CXXFLAGS="-std=gnu++0x"
else
if test "$ax_cv_cxx_compile_cxx0x_cxx" = "yes"; then
	LIBPAGECACHE_CXXFLAGS="-std=c++0x"
else
	if test "$ax_cv_cxx_compile_cxx0x_gxx" != "yes"; then
	# don't warn about deprecated g++ APIs, obsoleted by c++0x
	LIBPAGECACHE_CXXFLAGS="-Wno-deprecated"
	fi
fi
fi

AC_SUBST(LIBPAGECACHE_CPPFLAGS)
AC_SUBST(LIBPAGECACHE_CXXFLAGS)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
