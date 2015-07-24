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
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <dlog.h>

#include "debug.h"
#include "packet.h"
#include "util.h"

int errno;

struct data {
	struct {
		int version;
		int payload_size;
		char command[PACKET_MAX_CMD];
		enum packet_type type;
		enum packet_flag flag;
		double seq;
		unsigned long source;
		unsigned long destination;
		unsigned long mask;
	} head;

	char payload[];
};

struct packet {
	enum {
		VALID = 0xbeefbeef,
		INVALID = 0xdeaddead
	} state;
	int refcnt;
	void (*close_fd_cb)(int fd, void *data);
	void *close_fd_cbdata;
	int fd;
	struct data *data;
};

EAPI const enum packet_type const packet_type(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return PACKET_ERROR;
	}

	return packet->data->head.type;
}

EAPI unsigned long packet_mask(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return 0;
	}

	return packet->data->head.mask;
}

EAPI int packet_set_mask(struct packet *packet, unsigned long mask)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return -EINVAL;
	}

	packet->data->head.mask = mask;
	return 0;
}

EAPI const enum packet_flag const packet_flag(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return PACKET_FLAG_ERROR;
	}

	return packet->data->head.flag;
}

EAPI int packet_set_flag(struct packet *packet, enum packet_flag flag)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return -EINVAL;
	}

	packet->data->head.flag = flag;
	return 0;
}

EAPI const unsigned long const packet_source(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return 0;
	}

	return packet->data->head.source;
}

EAPI int packet_set_source(struct packet *packet, unsigned long source)
{
	if (!packet || packet->state != VALID || !packet->data || !source) {
		return -EINVAL;
	}

	packet->data->head.source = source;
	return 0;
}

EAPI int packet_set_fd(struct packet *packet, int fd)
{
	if (!packet || packet->state != VALID || !packet->data || fd < 0) {
		return -EINVAL;
	}

	packet->fd = fd;
	return 0;
}

EAPI int packet_fd(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return -EINVAL;
	}

	return packet->fd;
}

EAPI int packet_set_fd_close_handler_on_destroy(struct packet *packet, void (*close_cb)(int fd, void *data), void *data)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return -EINVAL;
	}

	packet->close_fd_cb = close_cb;
	packet->close_fd_cbdata = data;
	return 0;
}

EAPI const unsigned long const packet_destination(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return 0;
	}

	return packet->data->head.destination;
}

EAPI int packet_set_destination(struct packet *packet, unsigned long destination)
{
	if (!packet || packet->state != VALID || !packet->data || !destination) {
		return -EINVAL;
	}

	packet->data->head.destination = destination;
	return 0;
}

EAPI const int const packet_version(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return PACKET_ERROR;
	}

	return packet->data->head.version;
}

EAPI const int const packet_header_size(void)
{
	struct data payload; /* Only for getting the size of header of packet */

	return sizeof(payload.head);
}

EAPI const int const packet_size(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return -EINVAL;
	}

	return sizeof(*packet->data) + packet->data->head.payload_size;
}

EAPI const double const packet_seq(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return 0;
	}

	return packet->data->head.seq;
}

EAPI const int const packet_payload_size(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return -EINVAL;
	}

	return packet->data->head.payload_size;
}

EAPI const char * const packet_command(const struct packet *packet)
{
	if (!packet || packet->state != VALID || !packet->data) {
		return NULL;
	}

	return packet->data->head.command;
}

EAPI const void * const packet_data(const struct packet *packet)
{
	if (!packet || packet->state != VALID) {
		return NULL;
	}

	return packet->data;
}

static inline __attribute__((always_inline)) struct data *check_and_expand_packet(struct data *packet, int *payload_size)
{
	struct data *new_packet;

	if (packet->head.payload_size < *payload_size) {
		return packet;
	}

	new_packet = realloc(packet, sizeof(*packet) + *payload_size + BUFSIZ); /*!< Expanding to +BUFSIZ */
	if (!new_packet) {
		ErrPrint("Heap: %s\n", strerror(errno));
		free(packet);
		return NULL;
	}

	*payload_size += BUFSIZ;
	return new_packet;
}

static inline struct packet *packet_body_filler(struct packet *packet, int payload_size, const char *ptr, va_list va)
{
	char *payload;
	char *str;
	int align;

	while (*ptr) {
		payload = packet->data->payload + packet->data->head.payload_size;

		switch (*ptr) {
		case 'i':
		case 'I':
			align = (unsigned long)payload & (sizeof(int) - 1);
			if (align) {
				align = sizeof(int) - align;
			}

			packet->data->head.payload_size += sizeof(int) + align;
			packet->data = check_and_expand_packet(packet->data, &payload_size);
			if (!packet->data) {
				packet->state = INVALID;
				free(packet);
				packet = NULL;
				goto out;
			}

			*((int *)(payload + align)) = (int)va_arg(va, int);
			break;
		case 's':
		case 'S':
			str = (char *)va_arg(va, char *);

			if (str) {
				packet->data->head.payload_size += strlen(str) + 1; /*!< Including NIL */
				packet->data = check_and_expand_packet(packet->data, &payload_size);
				if (!packet->data) {
					packet->state = INVALID;
					free(packet);
					packet = NULL;
					goto out;
				}

				strcpy(payload, str); /*!< Including NIL */
			} else {
				packet->data->head.payload_size += 1;
				packet->data = check_and_expand_packet(packet->data, &payload_size);
				if (!packet->data) {
					packet->state = INVALID;
					free(packet);
					packet = NULL;
					goto out;
				}

				payload[0] = '\0';
			}
			break;
		case 'd':
		case 'D':
			align = (unsigned long)payload & (sizeof(double) - 1);
			if (align) {
				align = sizeof(double) - align;
			}

			packet->data->head.payload_size += sizeof(double) + align;
			packet->data = check_and_expand_packet(packet->data, &payload_size);
			if (!packet->data) {
				packet->state = INVALID;
				free(packet);
				packet = NULL;
				goto out;
			}

			*((double *)(payload + align)) = (double)va_arg(va, double);
			break;
		default:
			ErrPrint("Invalid type [%c]\n", *ptr);
			packet->state = INVALID;
			free(packet->data);
			free(packet);
			packet = NULL;
			goto out;
		}

		ptr++;
	}

out:
	return packet;
}

EAPI struct packet *packet_create_reply(const struct packet *packet, const char *fmt, ...)
{
	int payload_size;
	struct packet *result;
	va_list va;

	if (!packet || packet->state != VALID) {
		return NULL;
	}

	result = malloc(sizeof(*result));
	if (!result) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	payload_size = sizeof(*result->data) + BUFSIZ;
	result->refcnt = 0;
	result->fd = -1;
	result->close_fd_cb = NULL;
	result->close_fd_cbdata = NULL;
	result->data = calloc(1, payload_size);
	if (!result->data) {
		ErrPrint("Heap: %s\n", strerror(errno));
		result->state = INVALID;
		free(result);
		return NULL;
	}

	result->state = VALID;
	result->data->head.source = packet->data->head.destination;
	result->data->head.destination = packet->data->head.source;
	result->data->head.mask = 0xFFFFFFFF;
	result->data->head.seq = packet->data->head.seq;
	result->data->head.type = PACKET_ACK;
	result->data->head.version = packet->data->head.version;
	if (packet->data->head.command[0] == PACKET_CMD_INT_TAG) {
		unsigned int *head_cmd = (unsigned int *)result->data->head.command;
		unsigned int *packet_cmd = (unsigned int *)packet->data->head.command;

		*head_cmd = *packet_cmd;
	} else {
		strcpy(result->data->head.command, packet->data->head.command); /* we don't need to use strncmp */
	}
	result->data->head.payload_size = 0;
	payload_size -= sizeof(*result->data);

	va_start(va, fmt);
	result = packet_body_filler(result, payload_size, fmt, va);
	va_end(va);

	return packet_ref(result);
}

EAPI int packet_swap_address(struct packet *packet)
{
	unsigned long tmp;

	if (!packet || packet->state != VALID) {
		return -EINVAL;
	}

	tmp = packet->data->head.source;
	packet->data->head.source = packet->data->head.destination;
	packet->data->head.destination = tmp;

	return 0;
}

EAPI struct packet *packet_create(const char *cmd, const char *fmt, ...)
{
	struct packet *packet;
	int payload_size;
	va_list va;

	if (strlen(cmd) >= PACKET_MAX_CMD) {
		ErrPrint("Command is too long\n");
		return NULL;
	}

	packet = malloc(sizeof(*packet));
	if (!packet) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	payload_size = sizeof(*packet->data) + BUFSIZ;
	packet->refcnt = 0;
	packet->fd = -1;
	packet->close_fd_cb = NULL;
	packet->close_fd_cbdata = NULL;
	packet->data = calloc(1, payload_size);
	if (!packet->data) {
		ErrPrint("Heap: %s\n", strerror(errno));
		packet->state = INVALID;
		free(packet);
		return NULL;
	}

	packet->state = VALID;
	packet->data->head.source = 0lu;
	packet->data->head.destination = 0lu;
	packet->data->head.mask = 0xFFFFFFFF;
	packet->data->head.seq = util_timestamp();
	packet->data->head.type = PACKET_REQ;
	packet->data->head.version = PACKET_VERSION;
	if (cmd[0] == PACKET_CMD_INT_TAG) {
		unsigned int *head_cmd = (unsigned int *)packet->data->head.command;
		unsigned int *in_cmd = (unsigned int *)cmd;

		*head_cmd = *in_cmd;
	} else {
		strncpy(packet->data->head.command, cmd, sizeof(packet->data->head.command));
	}
	packet->data->head.payload_size = 0;
	payload_size -= sizeof(*packet->data); /*!< Usable payload size (except head size) */

	va_start(va, fmt);
	packet = packet_body_filler(packet, payload_size, fmt, va);
	va_end(va);

	return packet_ref(packet);
}

EAPI struct packet *packet_create_noack(const char *cmd, const char *fmt, ...)
{
	int payload_size;
	struct packet *result;
	va_list va;

	if (strlen(cmd) >= PACKET_MAX_CMD) {
		ErrPrint("Command is too long\n");
		return NULL;
	}

	result = malloc(sizeof(*result));
	if (!result) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	payload_size = sizeof(*result->data) + BUFSIZ;
	result->refcnt = 0;
	result->fd = -1;
	result->close_fd_cb = NULL;
	result->close_fd_cbdata = NULL;
	result->data = calloc(1, payload_size);
	if (!result->data) {
		ErrPrint("Heap: %s\n", strerror(errno));
		result->state = INVALID;
		free(result);
		return NULL;
	}

	result->state = VALID;
	result->data->head.source = 0lu;
	result->data->head.destination = 0lu;
	result->data->head.mask = 0xFFFFFFFF;
	result->data->head.seq = util_timestamp();
	result->data->head.type = PACKET_REQ_NOACK;
	result->data->head.version = PACKET_VERSION;
	if (cmd[0] == PACKET_CMD_INT_TAG) {
		unsigned int *head_cmd = (unsigned int *)result->data->head.command;
		unsigned int *cmd_in = (unsigned int *)cmd;
		*head_cmd = *cmd_in;
	} else {
		strncpy(result->data->head.command, cmd, sizeof(result->data->head.command));
	}
	result->data->head.payload_size = 0;
	payload_size -= sizeof(*result->data);

	va_start(va, fmt);
	result = packet_body_filler(result, payload_size, fmt, va);
	va_end(va);

	return packet_ref(result);
}

EAPI int packet_get(const struct packet *packet, const char *fmt, ...)
{
	const char *ptr;
	va_list va;
	int ret = 0;
	char *payload;
	int offset = 0;
	int *int_ptr;
	double *double_ptr;
	char **str_ptr;
	int align;

	if (!packet || packet->state != VALID) {
		return -EINVAL;
	}

	va_start(va, fmt);

	ptr = fmt;
	while (*ptr && offset < packet->data->head.payload_size) {
		payload = packet->data->payload + offset;
		switch (*ptr) {
		case 'i':
		case 'I':
			align = (unsigned long)payload & (sizeof(int) - 1);
			if (align) {
				align = sizeof(int) - align;
			}

			int_ptr = (int *)va_arg(va, int *);
			*int_ptr = *((int *)(payload + align));
			offset += (sizeof(int) + align);
			ret++;
			break;
		case 'd':
		case 'D':
			align = (unsigned long)payload & (sizeof(double) - 1);
			if (align) {
				align = sizeof(double) - align;
			}
			double_ptr = (double *)va_arg(va, double *);
			*double_ptr = *((double *)(payload + align));
			offset += (sizeof(double) + align);
			ret++;
			break;
		case 's':
		case 'S':
			str_ptr = (char **)va_arg(va, char **);
			*str_ptr = payload;
			offset += (strlen(*str_ptr) + 1); /*!< Including NIL */
			ret++;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		ptr++;
	}

out:
	va_end(va);
	return ret;
}

EAPI struct packet *packet_ref(struct packet *packet)
{
	if (!packet || packet->state != VALID) {
		return NULL;
	}

	packet->refcnt++;
	return packet;
}

EAPI struct packet *packet_unref(struct packet *packet)
{
	if (!packet || packet->state != VALID) {
		return NULL;
	}

	packet->refcnt--;
	if (packet->refcnt < 0) {
		ErrPrint("Invalid refcnt\n");
		return NULL;
	}

	if (packet->refcnt == 0) {
		if (packet->close_fd_cb && packet->fd >= 0) {
			packet->close_fd_cb(packet->fd, packet->close_fd_cbdata);
		}

		packet->state = INVALID;
		free(packet->data);
		free(packet);
		return NULL;
	}

	return packet;
}

EAPI int packet_destroy(struct packet *packet)
{
	packet_unref(packet);
	return 0;
}

EAPI struct packet *packet_build(struct packet *packet, int offset, void *data, int size)
{
	char *ptr;

	if (packet == NULL) {
		if (offset) {
			ErrPrint("Invalid argument\n");
			return NULL;
		}

		packet = malloc(sizeof(*packet));
		if (!packet) {
			ErrPrint("Heap: %s\n", strerror(errno));
			return NULL;
		}

		packet->refcnt = 1;
		packet->fd = -1;
		packet->close_fd_cb = NULL;
		packet->close_fd_cbdata = NULL;
		packet->data = calloc(1, size);
		if (!packet->data) {
			ErrPrint("Heap: %s\n", strerror(errno));
			packet->state = INVALID;
			free(packet);
			return NULL;
		}

		packet->state = VALID;
		memcpy(packet->data, data, size);
		packet->data->head.mask = 0xFFFFFFFF;
		return packet;
	}

	ptr = realloc(packet->data, offset + size);
	if (!ptr) {
		ErrPrint("Heap: %s\n", strerror(errno));
		packet->state = INVALID;
		free(packet->data);
		free(packet);
		return NULL;
	}

	packet->data = (struct data *)ptr;
	memcpy(ptr + offset, data, size);

	return packet;
}

/* End of a file */
