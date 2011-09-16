#include "libpagecache-config.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "symbol.h"

/* returns the address of a symbol or dies */
void *find_symbol(const char *symbol)
{
	static void *libc_handle;
	char *error;
	void *addr;

	if (libc_handle == NULL) {
		libc_handle = dlopen("libc.so.6", RTLD_LAZY);
		if (libc_handle == NULL) {
			fprintf(stderr, "%s: %s\n", symbol, dlerror());
			exit(1);
		}
	}

	dlerror();
	addr = dlsym(libc_handle, symbol);
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s: %s\n", symbol, error);
		exit(1);
	}

	/* NULL may be a valid address of a symbol,
	   but we're not going to call it. */
	if (symbol == NULL) {
		fprintf(stderr, "%s: is a NULL pointer\n", symbol);
		exit(1);
	}

	return addr;
}
