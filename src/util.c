/*
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <dlog.h>

#include "debug.h"
#include "util.h"

int errno;
#if defined(_USE_ECORE_TIME_GET)
static struct {
	clockid_t type;
} s_info = {
	.type = CLOCK_MONOTONIC,
};
#endif

const char *util_basename(const char *name)
{
	int length;
	length = name ? strlen(name) : 0;
	if (!length)
		return ".";

	while (--length > 0 && name[length] != '/');

	return length <= 0 ? name : name + length + (name[length] == '/');
}

double util_timestamp(void)
{
#if defined(_USE_ECORE_TIME_GET)
	struct timespec ts;

	do {
		if (clock_gettime(s_info.type, &ts) == 0) {
			return ts.tv_sec + ts.tv_nsec / 1000000000.0f;
		}

		ErrPrint("%d: %s\n", s_info.type, strerror(errno));
		if (s_info.type == CLOCK_MONOTONIC) {
			s_info.type = CLOCK_REALTIME;
		} else if (s_info.type == CLOCK_REALTIME) {
			struct timeval tv;
			if (gettimeofday(&tv, NULL) < 0) {
				ErrPrint("gettimeofday: %s\n", strerror(errno));
				break;
			}

			return tv.tv_sec + tv.tv_usec / 1000000.0f;
		}
	} while (1);

	return 0.0f;
#else
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0) {
		ErrPrint("gettimeofday: %s\n", strerror(errno));
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	}

	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0f;
#endif
}

/* End of a file */
