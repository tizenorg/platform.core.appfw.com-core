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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>

#include <glib.h>
#include <dlog.h>

#include "debug.h"
#include "com-core.h"
#include "com-core_thread.h"
#include "packet.h"
#include "secure_socket.h"
#include "dlist.h"
#include "com-core_packet.h"
#include "util.h"

#define DEFAULT_TIMEOUT 2.0f
/**
 * @brief
 * If the first character is started with 0x01,
 * The command string should be treated as a index of command table.
 */

static struct info {
	struct dlist *recv_list;
	struct dlist *request_list;
	char *addr;

	struct {
		int (*server_create)(const char *addr, int is_sync, const char *label, int (*service_cb)(int fd, void *data), void *data);
		int (*client_create)(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data);
		int (*client_create_by_fd)(int fd, int is_sync, int (*service_cb)(int fd, void *data), void *data);
		int (*server_destroy)(int handle);
		int (*client_destroy)(int handle);

		int (*recv)(int handle, char *buffer, int size, int *sender_pid, double timeout);
		int (*send)(int handle, const char *buffer, int size, double timeout);

		int (*recv_with_fd)(int handle, char *buffer, int size, int *sender_pid, double timeout, int *fd);
		int (*send_with_fd)(int handle, const char *buffer, int size, double timeout, int fd);
	} vtable;

	int initialized;
} s_info = {
	.recv_list = NULL,
	.request_list = NULL,
	.addr = NULL,
	.vtable = {
		.server_create = com_core_server_create,
		.client_create = com_core_client_create,
		.client_create_by_fd = com_core_client_create_by_fd,
		.server_destroy = com_core_server_destroy,
		.client_destroy = com_core_client_destroy,
		.recv = com_core_recv,
		.send = com_core_send,
		.recv_with_fd = com_core_recv_with_fd,
		.send_with_fd = com_core_send_with_fd,
	},
	.initialized = 0,
};

struct request_ctx {
	pid_t pid;
	int handle;

	struct packet *packet;
	int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data);
	void *data;

	int inuse;
};

struct recv_ctx {
	enum {
		RECV_STATE_INIT,
		RECV_STATE_HEADER,
		RECV_STATE_BODY,
		RECV_STATE_READY
	} state;
	int handle;
	int offset;
	pid_t pid;
	struct packet *packet;
	double timeout;

	int inuse;
};

static inline struct request_ctx *find_request_ctx(int handle, double seq)
{
	struct request_ctx *ctx;
	struct dlist *l;

	dlist_foreach(s_info.request_list, l, ctx) {
		if (ctx->handle == handle && packet_seq(ctx->packet) == seq) {
			return ctx;
		}
	}

	return NULL;
}

static inline void destroy_request_ctx(struct request_ctx *ctx)
{
	struct dlist *l;

	if (ctx->inuse) {
		return;
	}

	l = dlist_find_data(s_info.request_list, ctx);
	if (!l) {
		return;
	}

	s_info.request_list = dlist_remove(s_info.request_list, l);

	packet_unref(ctx->packet);
	free(ctx);
}

static inline struct request_ctx *create_request_ctx(int handle)
{
	struct request_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	ctx->handle = handle;
	ctx->pid = (pid_t)-1;
	ctx->packet = NULL;
	ctx->recv_cb = NULL;
	ctx->data = NULL;
	ctx->inuse = 0;

	s_info.request_list = dlist_append(s_info.request_list, ctx);
	return ctx;
}

static inline struct recv_ctx *find_recv_ctx(int handle)
{
	struct recv_ctx *ctx;
	struct dlist *l;

	dlist_foreach(s_info.recv_list, l, ctx) {
		if (ctx->handle == handle) {
			return ctx;
		}
	}

	return NULL;
}

static inline void recreate_recv_ctx(struct recv_ctx *ctx)
{
	if (ctx->packet) {
		packet_destroy(ctx->packet);
		ctx->packet = NULL;
	}
	ctx->state = RECV_STATE_INIT;
	ctx->offset = 0;
	ctx->pid = (pid_t)-1;
	// ctx->inuse
	// ctx->handle
	// ctx->timeout
}

static inline void destroy_recv_ctx(struct recv_ctx *ctx)
{
	struct dlist *l;

	if (ctx->inuse) {
		return;
	}

	l = dlist_find_data(s_info.recv_list, ctx);
	if (!l) {
		return;
	}

	s_info.recv_list = dlist_remove(s_info.recv_list, l);

	packet_destroy(ctx->packet);
	free(ctx);
}

static inline struct recv_ctx *create_recv_ctx(int handle, double timeout)
{
	struct recv_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		ErrPrint("heap: %s\n", strerror(errno));
		return NULL;
	}

	ctx->state = RECV_STATE_INIT,
		ctx->offset = 0;
	ctx->packet = NULL;
	ctx->handle = handle;
	ctx->pid = (pid_t)-1;
	ctx->timeout = timeout;
	ctx->inuse = 0;

	s_info.recv_list = dlist_append(s_info.recv_list, ctx);
	return ctx;
}

static inline int packet_ready(int handle, struct recv_ctx *receive, struct method *table)
{
	struct request_ctx *request;
	double sequence;
	struct packet *result;
	register int i;
	int ret;
	const char *cmd;
	unsigned int cmd_idx;

	ret = 0;

	switch (packet_type(receive->packet)) {
	case PACKET_ACK:
		sequence = packet_seq(receive->packet);
		request = find_request_ctx(handle, sequence);
		if (!request) {
			ErrPrint("This is not requested packet (%s)\n", packet_command(receive->packet));
			break;
		}

		if (request->recv_cb) {
			request->inuse = 1;
			receive->inuse = 1;
			request->recv_cb(receive->pid, handle, receive->packet, request->data);
			receive->inuse = 0;
			request->inuse = 0;
		}

		destroy_request_ctx(request);
		break;
	case PACKET_REQ:
		cmd_idx = 0xFFFFFFFF;
		cmd = packet_command(receive->packet);
		if (cmd) {
			if (cmd[0] == PACKET_CMD_INT_TAG) {
				unsigned int *p_cmd_idx = (unsigned int *)cmd;

				/* Get rid of LSB 8 bits */
				cmd_idx = *p_cmd_idx >> 8;
			} else {
				for (i = 0; table[i].cmd; i++) {
					if (strcmp(table[i].cmd, cmd)) {
						continue;
					}

					cmd_idx = (unsigned int)i;
					break;
				}
			}
		}

		if (cmd_idx != 0xFFFFFFFF) {
			receive->inuse = 1;
			result = table[cmd_idx].handler(receive->pid, handle, receive->packet);
			receive->inuse = 0;
			if (result) {
				if (packet_fd(result) >= 0) {
					ret = s_info.vtable.send_with_fd(handle, (void *)packet_data(result), packet_size(result), DEFAULT_TIMEOUT, packet_fd(result));
				} else {
					ret = s_info.vtable.send(handle, (void *)packet_data(result), packet_size(result), DEFAULT_TIMEOUT);
				}

				if (ret < 0) {
					ErrPrint("Failed to send an ack packet\n");
				} else {
					ret = 0;
				}
				packet_destroy(result);
			}
		}

		break;
	case PACKET_REQ_NOACK:
		cmd_idx = 0xFFFFFFFF;
		cmd = packet_command(receive->packet);
		if (cmd) {
			if (cmd[0] == PACKET_CMD_INT_TAG) {
				unsigned int *p_cmd_idx = (unsigned int *)cmd;

				/* Get rid of LSB 8 bits */
				cmd_idx = *p_cmd_idx >> 8;
			} else {
				for (i = 0; table[i].cmd; i++) {
					if (strcmp(table[i].cmd, cmd)) {
						continue;
					}

					cmd_idx = (unsigned int)i;
					break;
				}
			}
		}

		if (cmd_idx != 0xFFFFFFFF) {
			receive->inuse = 1;
			result = table[cmd_idx].handler(receive->pid, handle, receive->packet);
			receive->inuse = 0;
			if (result) {
				packet_destroy(result);
			}
		}
		break;
	default:
		break;
	}

	/*!
	 * Return negative value will make call the disconnected_cb
	 */
	return ret;
}

static int client_disconnected_cb(int handle, void *data)
{
	struct recv_ctx *receive;
	struct request_ctx *request;
	struct dlist *l;
	struct dlist *n;
	int inuse_found = 0;
	pid_t pid = (pid_t)-1;

	receive = find_recv_ctx(handle);
	if (receive) {
		pid = receive->pid;
	}

	DbgPrint("Clean up all requests and a receive context for handle(%d) for pid(%d)\n", handle, pid);

	dlist_foreach_safe(s_info.request_list, l, n, request) {
		if (request->handle != handle) {
			continue;
		}

		if (request->inuse) {
			inuse_found = 1;
			continue;
		}

		if (request->recv_cb) {
			request->recv_cb(pid, handle, NULL, request->data);
		}

		destroy_request_ctx(request);
	}

	if (receive && !inuse_found) {
		destroy_recv_ctx(receive);
	}

	return 0;
}

static int service_cb(int handle, void *data)
{
	struct recv_ctx *receive;
	pid_t pid;
	int ret;
	int size;
	char *ptr;
	int fd = -1;

	receive = find_recv_ctx(handle);
	if (!receive) {
		receive = create_recv_ctx(handle, DEFAULT_TIMEOUT);
		if (!receive) {
			ErrPrint("Couldn't find or create a receive context\n");
			return -EIO;
		}
	}

	switch (receive->state) {
	case RECV_STATE_INIT:
		receive->state = RECV_STATE_HEADER;
		receive->offset = 0;
	case RECV_STATE_HEADER:
		size = packet_header_size() - receive->offset;
		/*!
		 * \note
		 * Getting header
		 */
		ptr = malloc(size);
		if (!ptr) {
			ErrPrint("Heap: %s (%d)\n", strerror(errno), size);
			return -ENOMEM;
		}

		ret = s_info.vtable.recv_with_fd(handle, ptr, size, &pid, receive->timeout, &fd);
		if (ret < 0) {
			ErrPrint("Recv[%d], pid[%d :: %d]\n", ret, receive->pid, pid);
			free(ptr);
			return -EIO; /*!< Return negative value will invoke the client_disconnected_cb */
		} else if (ret > 0) {
			if (receive->pid != -1 && receive->pid != pid) {
				ErrPrint("Recv[%d], pid[%d :: %d]\n", ret, receive->pid, pid);
				free(ptr);
				return -EIO; /*!< Return negative value will invoke the client_disconnected_cb */
			}

			receive->pid = pid;
			receive->packet = packet_build(receive->packet, receive->offset, ptr, ret);
			free(ptr);

			if (!receive->packet) {
				ErrPrint("Built packet is not valid\n");
				return -EFAULT; /*!< Return negative value will invoke the client_disconnected_cb */
			}

			if (fd >= 0) {
				if (packet_fd(receive->packet) >= 0) {
					DbgPrint("Packet already has FD: %d (new: %d)\n", packet_fd(receive->packet), fd);
				}

				packet_set_fd(receive->packet, fd);
			}

			receive->offset += ret;

			if (receive->offset == packet_header_size()) {
				if (packet_size(receive->packet) == receive->offset) {
					receive->state = RECV_STATE_READY;
				} else {
					receive->state = RECV_STATE_BODY;
				}
			}
		} else {
			DbgPrint("ZERO bytes receives(%d)\n", pid);
			free(ptr);
			return -ECONNRESET;
		}
		break;
	case RECV_STATE_BODY:
		size = packet_size(receive->packet) - receive->offset;
		if (size == 0) {
			receive->state = RECV_STATE_READY;
			break;
		}
		/*!
		 * \note
		 * Getting body
		 */
		ptr = malloc(size);
		if (!ptr) {
			ErrPrint("Heap: %s (%d)\n", strerror(errno), size);
			return -ENOMEM;
		}

		ret = s_info.vtable.recv_with_fd(handle, ptr, size, &pid, receive->timeout, &fd);
		if (ret < 0) {
			ErrPrint("Recv[%d], pid[%d :: %d]\n", ret, receive->pid, pid);
			free(ptr);
			return -EIO;
		} else if (ret > 0) {
			if (receive->pid != pid) {
				ErrPrint("Recv[%d], pid[%d :: %d]\n", ret, receive->pid, pid);
				free(ptr);
				return -EIO;
			}

			receive->packet = packet_build(receive->packet, receive->offset, ptr, ret);
			free(ptr);

			if (!receive->packet) {
				ErrPrint("Built packet is not valid\n");
				return -EFAULT;
			}

			if (fd >= 0) {
				if (packet_fd(receive->packet) >= 0) {
					DbgPrint("Packet already has FD: %d (new: %d)\n", packet_fd(receive->packet), fd);
				}

				packet_set_fd(receive->packet, fd);
			}

			receive->offset += ret;

			if (receive->offset == packet_size(receive->packet)) {
				receive->state = RECV_STATE_READY;
			}
		} else {
			DbgPrint("ZERO bytes receives(%d)\n", pid);
			free(ptr);
			return -ECONNRESET;
		}

		break;
	case RECV_STATE_READY:
	default:
		break;
	}

	if (receive->state == RECV_STATE_READY) {
		ret = packet_ready(handle, receive, data);
		if (ret == 0) {
			/*!
			 * If ret is negative value, the receive context will be destroyed from disconnected callback
			 */
			recreate_recv_ctx(receive);
		}
		/*!
		 * if ret is negative value, disconnected_cb will be called after this function
		 */
	} else {
		ret = 0;
	}

	return ret;
}

EAPI int com_core_packet_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data)
{
	int ret;
	struct request_ctx *ctx;

	if (handle < 0 || !packet) {
		ErrPrint("Invalid argument\n");
		return -EINVAL;
	}

	if (packet_type(packet) != PACKET_REQ) {
		ErrPrint("Invalid packet - should be PACKET_REQ\n");
		return -EINVAL;
	}

	ctx = create_request_ctx(handle);
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->recv_cb = recv_cb;
	ctx->data = data;
	ctx->packet = packet_ref(packet);

	if (packet_fd(packet) >= 0) {
		ret = s_info.vtable.send_with_fd(handle, (void *)packet_data(packet), packet_size(packet), DEFAULT_TIMEOUT, packet_fd(packet));
	} else {
		ret = s_info.vtable.send(handle, (void *)packet_data(packet), packet_size(packet), DEFAULT_TIMEOUT);
	}
	if (ret != packet_size(packet)) {
		ErrPrint("Send failed. %d <> %d (handle: %d)\n", ret, packet_size(packet), handle);
		destroy_request_ctx(ctx);
		return -EIO;
	}

	return 0;
}

EAPI int com_core_packet_send_only(int handle, struct packet *packet)
{
	int ret;

	if (packet_type(packet) != PACKET_REQ_NOACK) {
		ErrPrint("Invalid type - should be PACKET_REQ_NOACK (%p)\n", packet);
		return -EINVAL;
	}

	if (packet_fd(packet) >= 0) {
		ret = s_info.vtable.send_with_fd(handle, (void *)packet_data(packet), packet_size(packet), DEFAULT_TIMEOUT, packet_fd(packet));
	} else {
		ret = s_info.vtable.send(handle, (void *)packet_data(packet), packet_size(packet), DEFAULT_TIMEOUT);
	}
	if (ret != packet_size(packet)) {
		ErrPrint("Failed to send whole packet\n");
		return -EIO;
	}

	return 0;
}

EAPI struct packet *com_core_packet_oneshot_send(const char *addr, struct packet *packet, double timeout)
{
	int ret;
	int fd;
	pid_t pid;
	int offset;
	struct packet *result = NULL;
	void *ptr;
	int size;
	int recv_fd = -1;

	if (!addr || !packet) {
		ErrPrint("Invalid argument\n");
		return NULL;
	}

	fd = secure_socket_create_client(addr);
	if (fd < 0) {
		return NULL;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("fcntl: %s\n", strerror(errno));
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (packet_fd(packet) >= 0) {
		ret = com_core_send_with_fd(fd, (char *)packet_data(packet), packet_size(packet), DEFAULT_TIMEOUT, packet_fd(packet));
	} else {
		ret = com_core_send(fd, (char *)packet_data(packet), packet_size(packet), DEFAULT_TIMEOUT);
	}
	if (ret < 0) {
		goto out;
	}

	ptr = malloc(packet_header_size());
	if (!ptr) {
		ErrPrint("Heap: %s (%d)\n", strerror(errno), packet_header_size());
		goto out;
	}

	offset = 0;
	ret = com_core_recv_with_fd(fd, (char *)ptr, packet_header_size(), &pid, timeout, &recv_fd);
	if (ret <= 0) {
		DbgPrint("Recv returns %d\n", ret);
		free(ptr);
		goto out;
	} else {
		DbgPrint("Recv'd size: %d (header: %d) pid: %d, fd: %d\n", ret, packet_header_size(), pid, recv_fd);
		result = packet_build(result, offset, ptr, ret);
		offset += ret;
		free(ptr);
		if (!result) {
			ErrPrint("Failed to build a packet\n");
			goto out;
		}

		if (recv_fd >= 0) {
			if (packet_fd(result) >= 0) {
				DbgPrint("Packet already has FD: %d (new: %d)\n", packet_fd(result), recv_fd);
			}

			DbgPrint("Update FD: %d\n", recv_fd);
			packet_set_fd(result, recv_fd);
		}
	}

	size = packet_payload_size(result);
	if (size < 0) {
		packet_destroy(result);
		result = NULL;
		goto out;
	}

	if (size == 0) {
		DbgPrint("Has no payload\n");
		goto out;
	}

	ptr = malloc(size);
	if (!ptr) {
		ErrPrint("Heap: %s (%d)\n", strerror(errno), size);
		packet_destroy(result);
		result = NULL;
		goto out;
	}

	ret = com_core_recv_with_fd(fd, (char *)ptr, size, &pid, timeout, &recv_fd);
	if (ret <= 0) {
		DbgPrint("Recv returns %d\n", ret);
		free(ptr);
		packet_destroy(result);
		result = NULL;
	} else {
		DbgPrint("Recv'd %d bytes (pid: %d), fd: %d\n", ret, pid, recv_fd);
		result = packet_build(result, offset, ptr, ret);
		offset += ret;
		free(ptr);

		if (result && recv_fd >= 0) {
			if (packet_fd(result) >= 0) {
				DbgPrint("Packet already has FD: %d (new: %d)\n", packet_fd(result), recv_fd);
			}

			DbgPrint("Update FD: %d\n", recv_fd);
			packet_set_fd(result, recv_fd);
		}
	}

out:
	secure_socket_destroy_handle(fd);
	DbgPrint("Close connection: %d (recv_fd: %d)\n", fd, recv_fd);
	return result;
}

static inline int com_core_packet_init(void)
{
	int ret;
	if (s_info.initialized) {
		return 0;
	}

	ret = com_core_add_event_callback(CONNECTOR_DISCONNECTED, client_disconnected_cb, NULL);
	s_info.initialized = (ret == 0);
	return ret;
}

static inline int com_core_packet_fini(void)
{
	if (!s_info.initialized) {
		return 0;
	}

	s_info.initialized = 0;
	com_core_del_event_callback(CONNECTOR_DISCONNECTED, client_disconnected_cb, NULL);
	return 0;
}

EAPI int com_core_packet_client_init(const char *addr, int is_sync, struct method *table)
{
	int ret;

	ret = com_core_packet_init();
	if (ret < 0) {
		return ret;
	}

	ret = s_info.vtable.client_create(addr, is_sync, service_cb, table);
	if (ret < 0) {
		com_core_packet_fini();
	}

	return ret;
}

EAPI int com_core_packet_client_init_by_fd(int fd, int is_sync, struct method *table)
{
	int ret;

	ret = com_core_packet_init();
	if (ret < 0) {
		return ret;
	}

	ret = s_info.vtable.client_create_by_fd(fd, is_sync, service_cb, table);
	if (ret < 0) {
		com_core_packet_fini();
	}

	return ret;
}

EAPI int com_core_packet_client_fini(int handle)
{
	s_info.vtable.client_destroy(handle);
	com_core_packet_fini();
	return 0;
}

EAPI int com_core_packet_server_init(const char *addr, struct method *table)
{
	int ret;

	ret = com_core_packet_init();
	if (ret < 0) {
		return ret;
	}

	ret = s_info.vtable.server_create(addr, 0, NULL, service_cb, table);
	if (ret < 0) {
		com_core_packet_fini();
	}

	return ret;
}

EAPI int com_core_packet_server_init_with_permission(const char *addr, struct method *table, const char *label)
{
	int ret;

	ret = com_core_packet_init();
	if (ret < 0) {
		return ret;
	}

	ret = s_info.vtable.server_create(addr, 0, label, service_cb, table);
	if (ret < 0) {
		com_core_packet_fini();
	}

	return ret;
}

EAPI void com_core_packet_server_disconnect_handle(int handle)
{
	s_info.vtable.server_destroy(handle);
}

EAPI int com_core_packet_server_fini(int handle)
{
	s_info.vtable.server_destroy(handle);
	com_core_packet_fini();
	return 0;
}

EAPI void com_core_packet_use_thread(int flag)
{
	if (s_info.initialized) {
		ErrPrint("com-core method is in use\n");
		return;
	}

	if (!!flag) {
		s_info.vtable.server_create = com_core_thread_server_create;
		s_info.vtable.client_create = com_core_thread_client_create;
		s_info.vtable.client_create_by_fd = com_core_thread_client_create_by_fd;
		s_info.vtable.server_destroy = com_core_thread_server_destroy;
		s_info.vtable.client_destroy = com_core_thread_client_destroy;
		s_info.vtable.recv = com_core_thread_recv;
		s_info.vtable.send = com_core_thread_send;
		s_info.vtable.recv_with_fd = com_core_thread_recv_with_fd;
		s_info.vtable.send_with_fd = com_core_thread_send_with_fd;
	} else {
		s_info.vtable.server_create = com_core_server_create;
		s_info.vtable.client_create = com_core_client_create;
		s_info.vtable.client_create_by_fd = com_core_client_create_by_fd;
		s_info.vtable.server_destroy = com_core_server_destroy;
		s_info.vtable.client_destroy = com_core_client_destroy;
		s_info.vtable.recv = com_core_recv;
		s_info.vtable.send = com_core_send;
		s_info.vtable.recv_with_fd = com_core_recv_with_fd;
		s_info.vtable.send_with_fd = com_core_send_with_fd;
	}
}

/* End of a file */
