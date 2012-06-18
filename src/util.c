#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "util.h"

int errno;

const char *util_basename(const char *name)
{
	int length;
	length = name ? strlen(name) : 0;
	if (!length)
		return ".";

	while (--length > 0 && name[length] != '/');

	return length <= 0 ? name : name + length;
}

/* End of a file */
