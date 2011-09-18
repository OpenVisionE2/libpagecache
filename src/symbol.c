#include "libpagecache-config.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define SYMBOL_MAX_NAME 32
#define SYMBOL_CACHE_SIZE 32

struct symbol
{
	char name[SYMBOL_MAX_NAME];
	void *addr;
};

struct symbol symbol_cache[SYMBOL_CACHE_SIZE];
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

void *__libc_dlsym(void *handle, const char *symbol);

/* returns the address of a symbol or dies */
void *find_symbol(void *hnd, const char *symbol, void *repl)
{
	static void *libc_handle;
	char *error;
	void *addr;
	int i = 0;
	int free_idx = -1;

	if (libc_handle == NULL) {
		libc_handle = dlopen("libc.so.6", RTLD_LAZY);
		if (libc_handle == NULL) {
			fprintf(stderr, "%s: %s\n", symbol, dlerror());
			exit(1);
		}
	}
	dlerror();

	if (hnd == NULL)
		hnd = libc_handle;

	// lookup cache
	if (hnd == libc_handle) {
		pthread_mutex_lock(&cache_mutex);
		for (i = 0; i < SYMBOL_CACHE_SIZE; ++i) {
			if (repl && !symbol_cache[i].name[0]) {
				free_idx = i;
				break;
			}
			if (!strncmp(symbol, symbol_cache[i].name, SYMBOL_MAX_NAME)) {
				addr = symbol_cache[i].addr;
				if (repl)
					symbol_cache[i].addr = repl;
				pthread_mutex_unlock(&cache_mutex);
				return addr;
			}
		}
		if (free_idx == -1)
			pthread_mutex_unlock(&cache_mutex);
	}

	addr = __libc_dlsym(hnd, symbol);

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

	if (repl) {
		if (free_idx != -1) {
			strncpy(symbol_cache[i].name, symbol, SYMBOL_MAX_NAME);
			symbol_cache[i].addr = repl;
			pthread_mutex_unlock(&cache_mutex);
		}
		else {
			fprintf(stderr, "symbol_cache too small!!! abort\n");
			exit(1);
		}
	}

	return addr;
}

void *dlsym(void *handle, const char *symbol)
{
	return find_symbol(handle, symbol, NULL);
}
