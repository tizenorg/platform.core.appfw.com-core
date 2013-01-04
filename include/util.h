/*
 * Copyright 2012  Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern const char *util_basename(const char *name);

#define CRITICAL_SECTION_BEGIN(handle) \
do { \
	int ret; \
	ret = pthread_mutex_lock(handle); \
	if (ret != 0) \
		ErrPrint("Failed to lock: %s\n", strerror(ret)); \
} while (0)

#define CRITICAL_SECTION_END(handle) \
do { \
	int ret; \
	ret = pthread_mutex_unlock(handle); \
	if (ret != 0) \
		ErrPrint("Failed to unlock: %s\n", strerror(ret)); \
} while (0)

/* End of a file */
