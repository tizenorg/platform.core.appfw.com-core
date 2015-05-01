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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <unistd.h>
#include <sys/select.h>

#include <glib.h>
#include <dlog.h>

#include "secure_socket.h"
#include "dlist.h"
#include "packet.h"
#include "com-core.h"
#include "com-core_packet.h"
#include "debug.h"
#include "util.h"
#include "com-core_packet-router.h"

struct packet_item {
	pid_t pid;
	struct packet *packet;
};

struct route {
	unsigned long address;
	int handle;
	int invalid;
};

struct client {
	struct router *router;
	int handle;

	pthread_t thid;
};

struct recv_ctx {
	enum state {
		RECV_STATE_INIT,
		RECV_STATE_HEADER,
		RECV_STATE_BODY,
		RECV_STATE_READY
	} state;

	struct packet *packet;
	unsigned long offset;
	pid_t pid;

	double timeout;
};

struct request_ctx {
	pid_t pid;
	int handle;

	struct packet *packet;
	int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data);
	void *data;
};

struct router {
	int handle;

	char *sock;
	struct packet *(*service)(int handle, pid_t pid, const struct packet *packet, void *data);
	void *data;

	double timeout;

	pthread_mutex_t recv_packet_list_lock;
	struct dlist *recv_packet_list;

	pthread_mutex_t route_list_lock;
	struct dlist *route_list;

	pthread_mutex_t send_packet_list_lock;
	struct dlist *send_packet_list;

	int recv_pipe[PIPE_MAX];
	int send_pipe[PIPE_MAX];

	pthread_t send_thid;

	guint id;

	unsigned long count_of_dropped_packet;

	int is_server;
	union {
		struct {
			struct dlist *client_list;
			guint accept_id;
		} server; /*!< Only used by the server */

		struct {
			pthread_t thid;
		} client; /*!< Only used by the client */
	} info;
};

struct event_item {
	int (*evt_cb)(int handle, void *data);
	void *data;
};

static struct info {
	struct dlist *router_list;
	struct dlist *request_list;

	struct dlist *disconnected_list;
	struct dlist *connected_list;
	struct dlist *error_list;
} s_info = {
	.router_list = NULL,
	.request_list = NULL,

	.disconnected_list = NULL,
	.connected_list = NULL,
	.error_list = NULL,
};

static struct packet *get_recv_packet(struct router *router, int *handle, pid_t *pid);
static int put_recv_packet(struct router *router, int handle, struct packet *packet, pid_t pid);

static struct packet *get_send_packet(struct router *router, int *handle);
static int put_send_packet(struct router *router, int handle, struct packet *packet);

/*!
 * \note
 * Running thread: Main
 */
static inline int invoke_disconnected_cb(struct router *router, int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct event_item *item;
	struct route *route;
	int ret;

	CRITICAL_SECTION_BEGIN(&router->route_list_lock);

	dlist_foreach(router->route_list, l, route) {
		if (route->handle == handle) {
			/*!
			 * \NOTE
			 * Invalidate an entry in the routing table.
			 * Do not this entry from the routing table from here,.
			 * Because a user may not want to delete the entry without any notification.
			 * So we just left this invalid entry on the table.
			 * Then the user has to manage the routing table correctly 
			 * via connected/disconnected event callbacks.
			 */
			route->invalid = 1;
		}
	}

	CRITICAL_SECTION_END(&router->route_list_lock);

	/*!
	 * \NOTE
	 * Invoke the disconnected callback
	 */
	dlist_foreach_safe(s_info.disconnected_list, l, n, item) {
		ret = item->evt_cb(handle, item->data);
		if (ret < 0 && dlist_find_data(s_info.disconnected_list, item)) {
			s_info.disconnected_list = dlist_remove(s_info.disconnected_list, l);
			free(item);
		}
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline int invoke_connected_cb(struct router *router, int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct event_item *item;
	int ret;

	dlist_foreach_safe(s_info.connected_list, l, n, item) {
		ret = item->evt_cb(handle, item->data);
		if (ret < 0 && dlist_find_data(s_info.connected_list, item)) {
			s_info.connected_list = dlist_remove(s_info.connected_list, l);
			free(item);
		}
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline int invoke_error_cb(struct router *router, int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct event_item *item;
	int ret;

	dlist_foreach_safe(s_info.error_list, l, n, item) {
		ret = item->evt_cb(handle, item->data);
		if (ret < 0 && dlist_find_data(s_info.error_list, item)) {
			s_info.error_list = dlist_remove(s_info.error_list, l);
			free(item);
		}
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
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

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void destroy_request_ctx(struct request_ctx *ctx)
{
	packet_unref(ctx->packet);
	dlist_remove_data(s_info.request_list, ctx);
	free(ctx);
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void clear_request_ctx(int handle)
{
	struct request_ctx *ctx;
	struct dlist *l;
	struct dlist *n;

	dlist_foreach_safe(s_info.request_list, l, n, ctx) {
		if (ctx->handle != handle) {
			continue;
		}

		if (ctx->recv_cb) {
			ctx->recv_cb(-1, handle, NULL, ctx->data);
		}

		destroy_request_ctx(ctx);
	}
}

/*!
 * \NOTE
 * Running thread: Main
 */
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

	s_info.request_list = dlist_append(s_info.request_list, ctx);
	return ctx;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static struct router *find_router_by_handle(int handle)
{
	struct dlist *l;
	struct router *router;

	dlist_foreach(s_info.router_list, l, router) {
		if (router->is_server) {
			struct dlist *cl;
			struct client *client;
			/*!
			 * Find the client list
			 */
			dlist_foreach(router->info.server.client_list, cl, client) {
				if (client->handle == handle) {
					return router;
				}
			}
		} else if (router->handle == handle) {
			return router;
		}
	}

	return NULL;
}


/*!
 * \NOTE
 * Running thread: Main
 */
static gboolean packet_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	struct router *router = data;
	struct packet *packet;
	struct packet *result_packet;
	struct request_ctx *request;
	int evt_handle;
	int handle = -1;
	pid_t pid = (pid_t)-1;

	evt_handle = g_io_channel_unix_get_fd(src);
	if (evt_handle != router->recv_pipe[PIPE_READ]) {
		ErrPrint("Invalid FD\n");
		goto errout;
	}

	if (!(cond & G_IO_IN)) {
		DbgPrint("PIPE is not valid\n");
		goto errout;
	}

	if ((cond & G_IO_ERR) || (cond & G_IO_HUP) || (cond & G_IO_NVAL)) {
		DbgPrint("PIPE is not valid\n");
		goto errout;
	}

	packet = get_recv_packet(router, &handle, &pid);
	if (!packet) {
		(void)invoke_disconnected_cb(router, handle);
		clear_request_ctx(handle);
	} else {
		int ret;

		switch (packet_type(packet)) {
		case PACKET_ACK:
			request = find_request_ctx(handle, packet_seq(packet));
			if (!request) {
				ErrPrint("Unknown ack packet\n");
				packet_destroy(packet);
				break;
			}

			if (request->recv_cb) {
				request->recv_cb(pid, handle, packet, request->data);
			}

			destroy_request_ctx(request);
			break;
		case PACKET_REQ_NOACK:
			if (!router->service) {
				ErrPrint("Service callback is not registered\n");
				break;
			}

			result_packet = router->service(handle, pid, packet, router->data);
			if (result_packet) {
				ErrPrint("Invalid result packet\n");
				packet_destroy(result_packet);
			}
			break;
		case PACKET_REQ:
			if (!router->service) {
				ErrPrint("Service callback is not registered, client can be block\n");
				break;
			}

			result_packet = router->service(handle, pid, packet, router->data);
			if (!result_packet) {
				ErrPrint("REQUEST Packet has no ACK Packet, client can be block\n");
				break;
			}

			ret = put_send_packet(router, handle, packet);
			if (ret < 0) {
				ErrPrint("Failed to send a packet\n");
			}
			break;
		case PACKET_ERROR:
		default:
			ErrPrint("Invalid packet arrived\n");
			router->count_of_dropped_packet++;
			break;
		}
	}

	/*!
	 * \TODO:
	 * How could we disconnect from the client?
	 */
	packet_destroy(packet);
	return TRUE;

errout:
	router->service(handle, pid, NULL, router->data);
	return FALSE;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static struct packet *service_handler(int handle, pid_t pid, const struct packet *packet, void *data)
{
	struct method *table = data;
	struct packet *result;
	register int i;

	if (!packet) {
		DbgPrint("Connection is lost [%d] [%d]\n", handle, pid);
		return NULL;
	}

	result = NULL;

	const char *cmd = packet_command(packet);
	if (cmd) {
		for (i = 0; table[i].cmd; i++) {

			if (strcmp(table[i].cmd, cmd)) {
				continue;
			}

			result = table[i].handler(pid, handle, packet);
			break;
		}
	}

	return result;
}

/*!
 * \NOTE:
 * Running thread: Server or Client or Send thread
 */
static inline int select_event(int handle, double timeout)
{
	fd_set set;
	int status;
	int ret;

	FD_ZERO(&set);
	FD_SET(handle, &set);

	status = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	if (status != 0) {
		ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
	}
	if (timeout > 0.0f) {
		struct timeval tv;

		tv.tv_sec = (unsigned long)timeout;
		tv.tv_usec = (timeout - (unsigned long)timeout) * 1000000u;

		ret = select(handle + 1, NULL, &set, NULL, &tv);
	} else if (timeout == 0.0f) {
		ret = select(handle + 1, NULL, &set, NULL, NULL);
	} else {
		ErrPrint("Invalid timeout: %lf (it must be greater than 0.0)\n", timeout);
		status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (status != 0) {
			ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
		}
		return -EINVAL;
	}

	if (ret < 0) {
		ret = -errno;
		if (errno == EINTR) {
			DbgPrint("Select receives INTR\n");
			status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			return -EAGAIN;
		}

		ErrPrint("Error: %s\n", strerror(errno));
		status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (status != 0) {
			ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
		}
		return ret;
	} else if (ret == 0) {
		ErrPrint("Timeout expired\n");
		status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (status != 0) {
			ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
		}
		return -ETIMEDOUT;
	}
	status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if (status != 0) {
		ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
	}

	if (!FD_ISSET(handle, &set)) {
		ErrPrint("Unexpected handle is toggled\n");
		return -EINVAL;
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Send thread
 */
static void *send_main(void *data)
{
	struct router *router = data;
	struct packet *packet;
	int handle;
	int ret;

	while (1) {
		/*!
		 * \note
		 * select event has cancel point
		 */
		ret = select_event(router->send_pipe[PIPE_READ], 0.0f);
		if (ret == -EAGAIN) {
			continue;
		}

		if (ret < 0) {
			break;
		}

		packet = get_send_packet(router, &handle);
		if (!packet) {
			DbgPrint("NULL Packet. Terminate thread\n");
			break;
		}

		switch (packet_type(packet)) {
		case PACKET_REQ:
		case PACKET_REQ_NOACK:
			ret = com_core_send(handle, (void *)packet_data(packet), packet_size(packet), router->timeout);
			break;
		default:
			ret = -EINVAL;
			break;
		}

		packet_destroy(packet);
	}

	return (void *)(unsigned long)ret;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static struct router *create_router(const char *sock, int handle, struct method *table)
{
	struct router *router;
	GIOChannel *gio;
	int ret;

	router = calloc(1, sizeof(*router));
	if (!router) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	ret = pthread_mutex_init(&router->recv_packet_list_lock, NULL);
	if (ret != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(ret));
		free(router);
		return NULL;
	}

	ret = pthread_mutex_init(&router->route_list_lock, NULL);
	if (ret != 0) {
		ErrPrint("Mutex craetion failed: %s\n", strerror(ret));
		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	ret = pthread_mutex_init(&router->send_packet_list_lock, NULL);
	if (ret != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(ret));

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	router->sock = strdup(sock);
	if (!router->sock) {
		ErrPrint("Heap: %s\n", strerror(errno));
		ret = pthread_mutex_destroy(&router->send_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	ret = pipe2(router->recv_pipe, O_NONBLOCK | O_CLOEXEC);
	if (ret < 0) {
		ErrPrint("pipe2: %s\n", strerror(errno));
		free(router->sock);

		ret = pthread_mutex_destroy(&router->send_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	ret = pipe2(router->send_pipe, O_NONBLOCK | O_CLOEXEC);
	if (ret < 0) {
		ErrPrint("pipe2: %s\n", strerror(errno));
		free(router->sock);

		CLOSE_PIPE(router->recv_pipe);

		ret = pthread_mutex_destroy(&router->send_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	router->handle = handle;
	router->service = service_handler;
	router->data = table;

	gio = g_io_channel_unix_new(router->recv_pipe[PIPE_READ]);
	if (!gio) {
		CLOSE_PIPE(router->recv_pipe);
		CLOSE_PIPE(router->send_pipe);

		free(router->sock);

		ret = pthread_mutex_destroy(&router->send_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}
	g_io_channel_set_close_on_unref(gio, FALSE);

	router->id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, (GIOFunc)packet_cb, router);
	if (router->id == 0) {
		GError *err = NULL;
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);

		CLOSE_PIPE(router->recv_pipe);
		CLOSE_PIPE(router->send_pipe);

		free(router->sock);

		ret = pthread_mutex_destroy(&router->send_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	g_io_channel_unref(gio);

	s_info.router_list = dlist_append(s_info.router_list, router);

	ret = pthread_create(&router->send_thid, NULL, send_main, router);
	if (ret != 0) {
		ErrPrint("Failed to create a send thread: %s\n", strerror(ret));
		dlist_remove_data(s_info.router_list, router);

		g_source_remove(router->id);

		CLOSE_PIPE(router->recv_pipe);
		CLOSE_PIPE(router->send_pipe);

		free(router->sock);

		ret = pthread_mutex_destroy(&router->send_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0) {
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		}

		free(router);
		return NULL;
	}

	return router;
}

/*!
 * \NOTE
 * Running thread: Main
 *
 * Before call this, every thread which uses this router object must has to be terminated.
 */
static inline __attribute__((always_inline)) int destroy_router(struct router *router)
{
	int handle;
	int ret;

	ret = put_send_packet(router, -1, NULL);
	DbgPrint("Put NULL Packet to terminate send thread (%d)\n", ret);

	ret = pthread_join(router->send_thid, NULL);
	if (ret != 0) {
		ErrPrint("Join: %s\n", strerror(ret));
	}

	dlist_remove_data(s_info.router_list, router);

	if (router->id > 0) {
		g_source_remove(router->id);
	}

	CLOSE_PIPE(router->recv_pipe);
	CLOSE_PIPE(router->send_pipe);

	free(router->sock);

	ret = pthread_mutex_destroy(&router->send_packet_list_lock);
	if (ret != 0) {
		ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
	}

	ret = pthread_mutex_destroy(&router->recv_packet_list_lock);
	if (ret != 0) {
		ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
	}

	ret = pthread_mutex_destroy(&router->route_list_lock);
	if (ret != 0) {
		ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
	}

	handle = router->handle;
	free(router);

	return handle;
}

/*!
 * \NOTE
 * Running thread: Client / Server leaf thread
 */
static inline int route_packet(struct router *router, int handle, struct packet *packet)
{
	struct dlist *l;
	struct route *route;
	unsigned long destination;
	unsigned long source;
	unsigned long mask;
	int processed = 0;

	destination = packet_destination(packet);
	source = packet_source(packet);
	mask = packet_mask(packet);

	/*!
	 * \TODO
	 * Can we believe this source?
	 * Validate this source address if possible.
	 */

	if (destination && source) {
		CRITICAL_SECTION_BEGIN(&router->route_list_lock);

		dlist_foreach(router->route_list, l, route) {
			if (!route->invalid && (route->address & mask) == (destination & mask)) {
				/*!
				 * \NOTE
				 * This code is executed in the CRITICAL SECTION
				 * If possible, we have to do this from the out of the CRITICAL SECTION
				 * 
				 * This code can makes the system slow.
				 *
				 * We have to optimize the processing time in the CRITICAL SECTION
				 */
				if (put_send_packet(router, route->handle, packet) < 0) {
					ErrPrint("Failed to send whole packet\n");
				}

				processed++;
			}
		}

		CRITICAL_SECTION_END(&router->route_list_lock);
	}

	if (processed == 0) {
		DbgPrint("Drop a packet\n");
		router->count_of_dropped_packet++;
	}

	packet_destroy(packet);
	return 0;
}

/*!
 * \NOTE
 * Running Threads: Main / Client / Server
 */
static int put_send_packet(struct router *router, int handle, struct packet *packet)
{
	if (packet) {
		struct packet_item *item;

		item = malloc(sizeof(*item));
		if (!item) {
			packet_destroy(packet);
			return -ENOMEM;
		}

		item->packet = packet;
		item->pid = (pid_t)-1;

		CRITICAL_SECTION_BEGIN(&router->send_packet_list_lock);

		router->send_packet_list = dlist_append(router->send_packet_list, item);

		CRITICAL_SECTION_END(&router->send_packet_list_lock);
	}

	/*!
	 * \note
	 * Producing an event on event pipe
	 */
	if (write(router->send_pipe[PIPE_WRITE], &handle, sizeof(handle)) != sizeof(handle)) {
		ErrPrint("Failed to put an event: %s\n", strerror(errno));
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Client / Server leaf thread
 */
static int put_recv_packet(struct router *router, int handle, struct packet *packet, pid_t pid)
{
	/*!
	 * If a packet is NULL, the connection is terminated
	 */
	if (packet) {
		struct packet_item *item;

		item = malloc(sizeof(*item));
		if (!item) {
			packet_destroy(packet);
			return -ENOMEM;
		}

		item->packet = packet;
		item->pid = pid;

		CRITICAL_SECTION_BEGIN(&router->recv_packet_list_lock);

		router->recv_packet_list = dlist_append(router->recv_packet_list, item);

		CRITICAL_SECTION_END(&router->recv_packet_list_lock);
	}

	/*!
	 * \note
	 * Producing an event on event pipe
	 */
	if (write(router->recv_pipe[PIPE_WRITE], &handle, sizeof(handle)) != sizeof(handle)) {
		ErrPrint("Failed to put an event: %s\n", strerror(errno));
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Send thread
 */
static struct packet *get_send_packet(struct router *router, int *handle)
{
	struct packet *packet = NULL;
	struct dlist *l;
	struct packet_item *item;

	CRITICAL_SECTION_BEGIN(&router->send_packet_list_lock);

	l = dlist_nth(router->send_packet_list, 0);
	if (l) {
		item = dlist_data(l);
		router->send_packet_list = dlist_remove(router->send_packet_list, l);
		packet = item->packet;
		free(item);
	}

	CRITICAL_SECTION_END(&router->send_packet_list_lock);

	if (read(router->send_pipe[PIPE_READ], handle, sizeof(*handle)) != sizeof(*handle)) {
		ErrPrint("Failed to get an event: %s\n", strerror(errno));
	}

	return packet;
}

/*!
 * \NOTE
 * Running thread: Main thread
 */
static struct packet *get_recv_packet(struct router *router, int *handle, pid_t *pid)
{
	struct packet *packet = NULL;
	struct dlist *l;
	struct packet_item *item;

	CRITICAL_SECTION_BEGIN(&router->recv_packet_list_lock);

	l = dlist_nth(router->recv_packet_list, 0);
	if (l) {
		item = dlist_data(l);
		router->recv_packet_list = dlist_remove(router->recv_packet_list, l);

		packet = item->packet;
		if (pid) {
			*pid = item->pid;
		}

		free(item);
	}

	CRITICAL_SECTION_END(&router->recv_packet_list_lock);

	/*!
	 * \note
	 * Consuming an event from event pipe
	 * Even if we cannot get the packet(NULL), we should consuming event
	 * Because the NULL packet means disconnected
	 */
	if (read(router->recv_pipe[PIPE_READ], handle, sizeof(*handle)) != sizeof(*handle)) {
		ErrPrint("Failed to get an event: %s\n", strerror(errno));
	}

	return packet;
}

static inline int build_packet(int handle, struct recv_ctx *ctx)
{
	char *ptr;
	int size;
	int ret;

	switch (ctx->state) {
	case RECV_STATE_INIT:
		ctx->offset = 0;
		ctx->packet = NULL;
	case RECV_STATE_HEADER:
		size = packet_header_size() - ctx->offset;

		ptr = malloc(size);
		if (!ptr) {
			ErrPrint("Heap: %s\n", strerror(errno));
			return -ENOMEM;
		}

		ret = com_core_recv(handle, ptr, size, &ctx->pid, ctx->timeout);
		if (ret == 0) {
			free(ptr);
			return -ECONNRESET;
		} else if (ret < 0) {
			free(ptr);
			return ret;
		}

		ctx->packet = packet_build(ctx->packet, ctx->offset, ptr, ret);
		free(ptr);

		if (!ctx->packet) {
			return -EFAULT;
		}

		ctx->offset += ret;

		if (ctx->offset == packet_header_size()) {
			if (packet_size(ctx->packet) == ctx->offset) {
				ctx->state = RECV_STATE_READY;
			} else {
				ctx->state = RECV_STATE_BODY;
			}
		}
		break;
	case RECV_STATE_BODY:
		size = packet_size(ctx->packet) - ctx->offset;
		if (size == 0) {
			ctx->state = RECV_STATE_READY;
			break;
		}

		ptr = malloc(size);
		if (!ptr) {
			ErrPrint("Heap: %s\n", strerror(errno));
			return -ENOMEM;
		}

		ret = com_core_recv(handle, ptr, size, &ctx->pid, ctx->timeout);
		if (ret == 0) {
			free(ptr);
			return -ECONNRESET;
		} else if (ret < 0) {
			free(ptr);
			return ret;
		}

		ctx->packet = packet_build(ctx->packet, ctx->offset, ptr, ret);
		free(ptr);
		if (!ctx->packet) {
			return -EFAULT;
		}

		ctx->offset += ret;
		if (ctx->offset == packet_size(ctx->packet)) {
			ctx->state = RECV_STATE_READY;
		}

		break;
	case RECV_STATE_READY:
	default:
		break;
	}

	return 0;
}

static int router_common_main(struct router *router, int handle, struct recv_ctx *ctx)
{
	int ret;
	while (1) {
		/*!
		 * \note
		 * select event has cancel point
		 */
		ret = select_event(handle, ctx->timeout);
		if (ret == -EAGAIN) {
			continue;
		}

		if (ret < 0) {
			packet_destroy(ctx->packet);
			break;
		}
		/*!
		 * Build a packet
		 * And push it to the packet list
		 */
		ret = build_packet(handle, ctx);
		if (ret != 0) {
			packet_destroy(ctx->packet);
			break;
		}

		if (ctx->state == RECV_STATE_READY) {
			/*!
			 * \NOTE
			 *
			 * If the destination address is ZERO,
			 * Pull up the packet to this server.
			 */
			if (packet_destination(ctx->packet)) {
				route_packet(router, handle, ctx->packet);
			} else {
				put_recv_packet(router, handle, ctx->packet, ctx->pid);
			}

			ctx->state = RECV_STATE_INIT;
		}
	}

	put_recv_packet(router, handle, NULL, ctx->pid);
	return ret;
}

/*!
 * \NOTE
 * Running thread: Server thread
 */
static void *server_main(void *data)
{
	struct client *client = data;
	struct router *router = client->router;
	struct recv_ctx ctx;
	int ret;

	ctx.state = RECV_STATE_INIT;
	ctx.packet = NULL;
	ctx.timeout = router->timeout;
	ctx.pid = (pid_t)-1;

	ret = router_common_main(router, client->handle, &ctx);
	return (void *)(unsigned long)ret;
}

/*!
 * \NOTE
 * Running thread: Client thread
 */
static void *client_main(void *data)
{
	struct router *router = data;
	struct recv_ctx ctx;
	int ret;

	ctx.state = RECV_STATE_INIT;
	ctx.packet = NULL;
	ctx.timeout = router->timeout;
	ctx.offset = 0;
	ctx.pid = (pid_t)-1;

	ret = router_common_main(router, router->handle, &ctx);
	return (void *)(unsigned long)ret;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static gboolean accept_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	int handle;
	int fd;
	struct router *router = data;
	struct client *client;
	int status;

	handle = g_io_channel_unix_get_fd(src);

	if (!(cond & G_IO_IN)) {
		ErrPrint("Accept socket closed\n");
		(void)invoke_error_cb(router, handle);
		return FALSE;
	}

	if ((cond & G_IO_ERR) || (cond & G_IO_HUP) || (cond & G_IO_NVAL)) {
		DbgPrint("Socket connection is lost\n");
		(void)invoke_error_cb(router, handle);
		return FALSE;
	}

	DbgPrint("New connection is made: socket(%d)\n", handle);
	fd = secure_socket_get_connection_handle(handle);
	if (fd < 0) {
		ErrPrint("Failed to get client fd from socket\n");
		(void)invoke_error_cb(router, handle);
		return FALSE;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	client = calloc(1, sizeof(*client));
	if (!client) {
		ErrPrint("Heap: %s\n", strerror(errno));
		secure_socket_destroy_handle(fd);
		/*!
		 * \NOTE
		 * Just return TRUE to keep this accept handler
		 */
		return TRUE;
	}

	client->handle = fd;
	client->router = router;
	router->info.server.client_list = dlist_append(router->info.server.client_list, client);

	status = pthread_create(&client->thid, NULL, server_main, client);
	if (status != 0) {
		ErrPrint("Thread creation failed: %s\n", strerror(status));
		dlist_remove_data(router->info.server.client_list, client);
		secure_socket_destroy_handle(client->handle);
		free(client);
		/*!
		 * \NOTE
		 * Just return TRUE to keep this accept handler
		 */
		return TRUE;
	}

	(void)invoke_connected_cb(router, fd);
	return TRUE;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_server_init(const char *sock, double timeout, struct method *table)
{
	int handle;
	struct router *router;
	GIOChannel *gio;

	handle = secure_socket_create_server(sock);
	if (handle < 0) {
		return handle;
	}

	router = create_router(sock, handle, table);
	if (!router) {
		secure_socket_destroy_handle(handle);
		return -ENOMEM;
	}

	router->timeout = timeout;
	router->is_server = 1;

	gio = g_io_channel_unix_new(router->handle);
	if (!gio) {
		handle = destroy_router(router);
		secure_socket_destroy_handle(handle);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	router->info.server.accept_id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, (GIOFunc)accept_cb, router);
	if (router->info.server.accept_id == 0) {
		GError *err = NULL;
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);

		handle = destroy_router(router);
		secure_socket_destroy_handle(handle);
		return -EIO;
	}

	g_io_channel_unref(gio);
	return router->handle;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_client_init(const char *sock, double timeout, struct method *table)
{
	struct router *router;
	int handle;
	int status;

	handle = secure_socket_create_client(sock);
	if (handle < 0) {
		return handle;
	}

	router = create_router(sock, handle, table);
	if (!router) {
		secure_socket_destroy_handle(handle);
		return -ENOMEM;
	}

	router->timeout = timeout;
	router->is_server = 0;

	status = pthread_mutex_init(&router->recv_packet_list_lock, NULL);
	if (status != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(status));

		handle = destroy_router(router);
		secure_socket_destroy_handle(handle);
		return -EFAULT;
	}

	status = pthread_mutex_init(&router->route_list_lock, NULL);
	if (status != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(status));
		handle = destroy_router(router);
		secure_socket_destroy_handle(handle);
		return -EFAULT;
	}

	status = pthread_create(&router->info.client.thid, NULL, client_main, router);
	if (status != 0) {
		ErrPrint("Thread creation failed: %s\n", strerror(status));
		handle = destroy_router(router);
		secure_socket_destroy_handle(handle);
		return -EFAULT;
	}

	(void)invoke_connected_cb(router, router->handle);
	return router->handle;
}

EAPI void *com_core_packet_router_server_fini(int handle)
{
	struct router *router;
	void *data;
	int status;
	struct dlist *l;
	struct dlist *n;

	struct client *client;
	struct route *route;

	void *ret;

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("No such router\n");
		return NULL;
	}

	if (!router->is_server) {
		ErrPrint("Invalid object\n");
		return NULL;
	}

	if(router->info.server.accept_id > 0)
		g_source_remove(router->info.server.accept_id);

	dlist_foreach_safe(router->info.server.client_list, l, n, client) {
		router->info.server.client_list = dlist_remove(router->info.server.client_list, l);

		status = pthread_cancel(client->thid);
		if (status != 0) {
			ErrPrint("Failed to cacnel a thread: %s\n", strerror(errno));
		}

		ret = NULL;
		status = pthread_join(client->thid, &ret);
		if (status != 0) {
			ErrPrint("Failed to join a thread: %s\n", strerror(errno));
		}

		if (ret == PTHREAD_CANCELED) {
			DbgPrint("Thread is canceled\n");
			clear_request_ctx(client->handle);
		}

		secure_socket_destroy_handle(client->handle);
		free(client);
	}

	dlist_foreach_safe(router->route_list, l, n, route) {
		router->route_list = dlist_remove(router->route_list, l);
		free(route);
	}

	data = router->data;

	handle = destroy_router(router);
	secure_socket_destroy_handle(handle);

	return data;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI void *com_core_packet_router_client_fini(int handle)
{
	struct router *router;
	void *data;
	int status;
	struct dlist *l;
	struct dlist *n;

	struct route *route;

	void *ret = NULL;

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("No such router\n");
		return NULL;
	}

	if (router->is_server) {
		ErrPrint("Invalid object\n");
		return NULL;
	}

	status = pthread_cancel(router->info.client.thid);
	if (status != 0) {
		ErrPrint("Failed to cancel a thread: %s\n", strerror(errno));
	}

	status = pthread_join(router->info.client.thid, &ret);
	if (status != 0) {
		ErrPrint("Failed to join a thread: %s\n", strerror(errno));
	}

	if (ret == PTHREAD_CANCELED) {
		DbgPrint("Thread is canceled\n");
		clear_request_ctx(router->handle);
	}

	dlist_foreach_safe(router->route_list, l, n, route) {
		router->route_list = dlist_remove(router->route_list, l);
		free(route);
	}

	data = router->data;

	handle = destroy_router(router);
	secure_socket_destroy_handle(handle);

	return data;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data)
{
	struct request_ctx *ctx;
	struct router *router;
	int ret;

	if (handle < 0 || !packet) {
		return -EINVAL;
	}

	if (packet_type(packet) != PACKET_REQ) {
		ErrPrint("Invalid packet - should be PACKET_REQ\n");
		return -EINVAL;
	}

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Router is not available\n");
		return -EINVAL;
	}

	ctx = create_request_ctx(handle);
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->recv_cb = recv_cb;
	ctx->data = data;
	ctx->packet = packet_ref(packet);

	ret = put_send_packet(router, handle, packet);
	if (ret < 0) {
		destroy_request_ctx(ctx);
	}

	return ret;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_send_only(int handle, struct packet *packet)
{
	struct router *router;

	if (handle < 0 || !packet || packet_type(packet) != PACKET_REQ_NOACK) {
		return -EINVAL;
	}

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Rouer is not available\n");
		return -EINVAL;
	}

	return put_send_packet(router, handle, packet);
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI struct packet *com_core_packet_router_oneshot_send(const char *addr, struct packet *packet, double timeout)
{
	return com_core_packet_oneshot_send(addr, packet, timeout);
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_add_route(int handle, unsigned long address, int h)
{
	struct router *router;
	struct route *route;
	struct route *tmp;
	struct dlist *l;
	int found = 0;

	if (handle < 0 || !address || h < 0) {
		return -EINVAL;
	}

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Router is not exists\n");
		return -ENOENT;
	}

	route = malloc(sizeof(*route));
	if (!route) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return -ENOMEM;
	}

	route->address = address;
	route->handle = h;
	route->invalid = 0;

	CRITICAL_SECTION_BEGIN(&router->route_list_lock);

	dlist_foreach(router->route_list, l, tmp) {
		if (tmp->address == address) {
			found = 1;
			break;
		}
	}

	if (!found) {
		router->route_list = dlist_append(router->route_list, route);
	}

	CRITICAL_SECTION_END(&router->route_list_lock);

	if (found) {
		free(route);
		return -EEXIST;
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_del_route(int handle, unsigned long address)
{
	struct router *router;
	struct route *route;
	struct dlist *l;
	struct dlist *n;
	int found = 0;

	if (handle < 0 || !address) {
		return -EINVAL;
	}

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Router is not exists\n");
		return -ENOENT;
	}

	CRITICAL_SECTION_BEGIN(&router->route_list_lock);

	dlist_foreach_safe(router->route_list, l, n, route) {
		if (route->address != address) {
			continue;
		}

		router->route_list = dlist_remove(router->route_list, l);

		DbgPrint("Delete an entry from the table (%lu : %d)\n", route->address, route->handle);
		free(route);

		found = 1;
		break;
	}

	CRITICAL_SECTION_END(&router->route_list_lock);

	return found ? 0 : -ENOENT;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_update_route(int handle, unsigned long address, int h)
{
	struct router *router;
	struct route *route;
	struct dlist *l;
	int found = 0;

	if (handle < 0 || !address || h < 0) {
		return -EINVAL;
	}

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Router is not exists\n");
		return -ENOENT;
	}

	CRITICAL_SECTION_BEGIN(&router->route_list_lock);

	dlist_foreach(router->route_list, l, route) {
		if (route->address != address) {
			continue;
		}

		route->handle = h;
		route->invalid = 0;
		found = 1;
		break;
	}

	CRITICAL_SECTION_END(&router->route_list_lock);

	return found ? 0 : -ENOENT;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_add_event_callback(enum com_core_route_event_type type, int (*evt_cb)(int handle, void *data), void *data)
{
	struct event_item *item;

	if (!evt_cb) {
		ErrPrint("Invalid event callback\n");
		return -EINVAL;
	}

	item = malloc(sizeof(*item));
	if (!item) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return -ENOMEM;
	}

	item->evt_cb = evt_cb;
	item->data = data;

	switch (type) {
	case COM_CORE_ROUTE_CONNECTED:
		s_info.connected_list = dlist_prepend(s_info.connected_list, item);
		break;
	case COM_CORE_ROUTE_DISCONNECTED:
		s_info.disconnected_list = dlist_prepend(s_info.disconnected_list, item);
		break;
	case COM_CORE_ROUTE_ERROR:
		s_info.error_list = dlist_prepend(s_info.error_list, item);
		break;
	default:
		free(item);
		return -EINVAL;
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_del_event_callback(enum com_core_route_event_type type, int (*evt_cb)(int handle, void *data), void *data)
{
	struct dlist *l;
	struct dlist *n;
	struct event_item *item;

	switch (type) {
	case COM_CORE_ROUTE_CONNECTED:
		dlist_foreach_safe(s_info.connected_list, l, n, item) {
			if (item->evt_cb == evt_cb && item->data == data) {
				s_info.connected_list = dlist_remove(s_info.connected_list, l);
				free(item);
				return 0;
			}
		}
		break;
	case COM_CORE_ROUTE_DISCONNECTED:
		dlist_foreach_safe(s_info.disconnected_list, l, n, item) {
			if (item->evt_cb == evt_cb && item->data == data) {
				s_info.disconnected_list = dlist_remove(s_info.disconnected_list, l);
				free(item);
				return 0;
			}
		}
		break;
	case COM_CORE_ROUTE_ERROR:
		dlist_foreach_safe(s_info.error_list, l, n, item) {
			if (item->evt_cb == evt_cb && item->data == data) {
				s_info.error_list = dlist_remove(s_info.error_list, l);
				free(item);
				return 0;
			}
		}
		break;
	default:
		ErrPrint("Invalid event type\n");
		return -EINVAL;
	}

	return -ENOENT;
}

#undef _GNU_SOURCE
/* End of a file */
