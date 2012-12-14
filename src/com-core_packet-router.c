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

#define PIPE_READ 0
#define PIPE_WRITE 1

struct packet_item {
	pid_t pid;
	struct packet *packet;
};

struct route {
	int from;
	int to;
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
		RECV_STATE_READY,
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

	pthread_mutex_t packet_list_lock;
	struct dlist *packet_list;

	pthread_mutex_t route_list_lock;
	struct dlist *route_list;

	int evt_pipe[2];

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

static inline struct packet *get_packet(struct router *router, int *handle, pid_t *pid);
static inline int put_packet(struct router *router, int handle, struct packet *packet, pid_t pid);

/*!
 * \note
 * Running thread: Main
 */
static inline int invoke_disconnected_cb(struct router *router, int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct event_item *item;
	int ret;

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
		if (ctx->handle != handle)
			continue;

		if (ctx->recv_cb)
			ctx->recv_cb(-1, handle, NULL, ctx->data);

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
static inline struct router *find_router_by_handle(int handle)
{
	struct dlist *l;
	struct router *router;

	dlist_foreach(s_info.router_list, l, router) {
		if (router->handle == handle)
			return router;
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
	if (evt_handle != router->evt_pipe[PIPE_READ]) {
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

	packet = get_packet(router, &handle, &pid);
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

			if (request->recv_cb)
				request->recv_cb(pid, handle, packet, request->data);

			destroy_request_ctx(request);
			break;
		case PACKET_REQ_NOACK:
			if (!router->service) {
				ErrPrint("Service callback is not registered\n");
				break;
			}

			result_packet = router->service(handle, pid, packet, router->data);
			if (result_packet) {
				ErrPrint("This is not need result packet\n");
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

			ret = com_core_send(handle, (void *)packet_data(result_packet), packet_size(result_packet), router->timeout);
			if (ret != packet_size(result_packet))
				ErrPrint("Failed to send reply packet. client can be block\n");
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
	for (i = 0; table[i].cmd; i++) {
		if (strcmp(table[i].cmd, packet_command(packet)))
			continue;

		result = table[i].handler(pid, handle, packet);
		break;
	}

	return result;
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

	ret = pthread_mutex_init(&router->packet_list_lock, NULL);
	if (ret != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(ret));
		free(router);
		return NULL;
	}

	ret = pthread_mutex_init(&router->route_list_lock, NULL);
	if (ret != 0) {
		ErrPrint("Mutex craetion failed: %s\n", strerror(ret));
		ret = pthread_mutex_destroy(&router->packet_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));
		return NULL;
	}

	router->sock = strdup(sock);
	if (!router->sock) {
		ErrPrint("Heap: %s\n", strerror(errno));
		ret = pthread_mutex_destroy(&router->packet_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		free(router);
		return NULL;
	}

	ret = pipe2(router->evt_pipe, O_NONBLOCK | O_CLOEXEC);
	if (ret < 0) {
		ErrPrint("pipe2: %s\n", strerror(errno));
		free(router->sock);

		ret = pthread_mutex_destroy(&router->packet_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		free(router);
		return NULL;
	}

	router->handle = handle;
	router->service = service_handler;
	router->data = table;

	gio = g_io_channel_unix_new(router->evt_pipe[PIPE_READ]);
	if (!gio) {
		close(router->evt_pipe[PIPE_READ]);
		close(router->evt_pipe[PIPE_WRITE]);
		free(router->sock);

		ret = pthread_mutex_destroy(&router->packet_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

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
		close(router->evt_pipe[PIPE_READ]);
		close(router->evt_pipe[PIPE_WRITE]);
		free(router->sock);

		ret = pthread_mutex_destroy(&router->packet_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		ret = pthread_mutex_destroy(&router->route_list_lock);
		if (ret != 0)
			ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

		free(router);
		return NULL;
	}

	g_io_channel_unref(gio);

	s_info.router_list = dlist_append(s_info.router_list, router);
	return router;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline int destroy_router(struct router *router)
{
	int handle;
	int ret;

	dlist_remove_data(s_info.router_list, router);

	if (router->id > 0)
		g_source_remove(router->id);

	close(router->evt_pipe[PIPE_READ]);
	close(router->evt_pipe[PIPE_WRITE]);
	free(router->sock);

	ret = pthread_mutex_destroy(&router->packet_list_lock);
	if (ret != 0)
		ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

	ret = pthread_mutex_destroy(&router->route_list_lock);
	if (ret != 0)
		ErrPrint("Mutex destroy failed: %s\n", strerror(ret));

	handle = router->handle;
	free(router);

	return handle;
}

/*!
 * \NOTE
 * Running thread: Client / Server leaf thread
 */
static inline int route_packet(struct router *router, int from, struct packet *packet)
{
	struct dlist *l;
	struct route *route;
	int processed;
	int ret;

	processed = 0;
	dlist_foreach(router->route_list, l, route) {
		if (route->from != from)
			continue;

		if (route->to < 0)
			continue;

		ret = com_core_send(route->to, (void *)packet_data(packet), packet_size(packet), router->timeout);
		if (ret != packet_size(packet)) {
			ErrPrint("Failed to send whole packet\n");
			continue;
		}

		processed++;
	}

	if (processed == 0)
		router->count_of_dropped_packet++;

	packet_destroy(packet);
	return 0;
}

/*!
 * \NOTE
 * Running thread: Client / Server leaf thread
 */
static inline int put_packet(struct router *router, int handle, struct packet *packet, pid_t pid)
{
	/*!
	 * If a packet is NULL, the connection is terminated
	 */
	if (packet) {
		int status;
		struct packet_item *item;

		item = malloc(sizeof(*item));
		if (!item) {
			packet_destroy(packet);
			return -ENOMEM;
		}

		item->packet = packet;
		item->pid = pid;

		status = pthread_mutex_lock(&router->packet_list_lock);
		if (status != 0)
			ErrPrint("Failed to lock: %s\n", strerror(errno));

		router->packet_list = dlist_append(router->packet_list, item);

		status = pthread_mutex_unlock(&router->packet_list_lock);
		if (!status != 0)
			ErrPrint("Failed to unlock: %s\n", strerror(errno));
	}

	/*!
	 * \note
	 * Producing an event on event pipe
	 */
	if (write(router->evt_pipe[PIPE_WRITE], &handle, sizeof(handle)) != sizeof(handle))
		ErrPrint("Failed to put an event: %s\n", strerror(errno));

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main thread
 */
static inline struct packet *get_packet(struct router *router, int *handle, pid_t *pid)
{
	int status;
	struct packet *packet = NULL;
	struct dlist *l;
	struct packet_item *item;

	status = pthread_mutex_lock(&router->packet_list_lock);
	if (status != 0)
		ErrPrint("Failed to get lock: %s\n", strerror(errno));

	l = dlist_nth(router->packet_list, 0);
	if (l) {
		item = dlist_data(l);
		router->packet_list = dlist_remove(router->packet_list, l);

		packet = item->packet;
		if (pid)
			*pid = item->pid;

		free(item);
	}

	status = pthread_mutex_unlock(&router->packet_list_lock);
	if (!status != 0)
		ErrPrint("Failed to unlock: %s\n", strerror(errno));

	/*!
	 * \note
	 * Consuming an event from event pipe
	 * Even if we cannot get the packet(NULL), we should consuming event
	 * Because the NULL packet means disconnected
	 */
	if (read(router->evt_pipe[PIPE_READ], handle, sizeof(*handle)) != sizeof(*handle))
		ErrPrint("Failed to get an event: %s\n", strerror(errno));

	return packet;
}

/*!
 * \NOTE:
 * Running thread: Server or Client thread
 */
static inline int select_event(int handle, double timeout)
{
	fd_set set;
	int status;
	int ret;

	FD_ZERO(&set);
	FD_SET(handle, &set);

	status = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	if (status != 0)
		ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
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
		if (status != 0)
			ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
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
		if (status != 0)
			ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
		return ret;
	} else if (ret == 0) {
		ErrPrint("Timeout expired\n");
		status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (status != 0)
			ErrPrint("Failed to set cancelstate: %s\n", strerror(status));
		return -ETIMEDOUT;
	}
	status = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if (status != 0)
		ErrPrint("Failed to set cancelstate: %s\n", strerror(status));

	if (!FD_ISSET(handle, &set)) {
		ErrPrint("Unexpected handle is toggled\n");
		return -EINVAL;
	}

	return 0;
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

		if (!ctx->packet)
			return -EFAULT;

		ctx->offset += ret;

		if (ctx->offset == packet_header_size()) {
			if (packet_size(ctx->packet) == ctx->offset)
				ctx->state = RECV_STATE_READY;
			else
				ctx->state = RECV_STATE_BODY;
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
		if (!ctx->packet)
			return -EFAULT;

		ctx->offset += ret;
		if (ctx->offset == packet_size(ctx->packet))
			ctx->state = RECV_STATE_READY;

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
		if (ret == -EAGAIN)
			continue;

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
			if (packet_flag(ctx->packet) & PACKET_FLAG_ROUTE)
				route_packet(router, handle, ctx->packet);
			else
				put_packet(router, handle, ctx->packet, ctx->pid);

			ctx->state = RECV_STATE_INIT;
		}
	}

	put_packet(router, handle, NULL, ctx->pid);
	return ret;
}

/*!
 * \NOTE
 * Running thread: Server thread
 */
static void *router_server_main(void *data)
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
	return (void *)ret;
}

/*!
 * \NOTE
 * Running thread: Client thread
 */
static void *router_client_main(void *data)
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
	return (void *)ret;
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

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		ErrPrint("Error: %s\n", strerror(errno));

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		ErrPrint("Error: %s\n", strerror(errno));

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

	status = pthread_create(&client->thid, NULL, router_server_main, client);
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
EAPI int com_core_packet_router_server_create(const char *sock, double timeout, struct method *table)
{
	int handle;
	struct router *router;
	GIOChannel *gio;

	handle = secure_socket_create_server(sock);
	if (handle < 0)
		return handle;

	router = create_router(sock, handle, table);
	if (!router) {
		secure_socket_destroy_handle(handle);
		return -ENOMEM;
	}

	router->timeout = timeout;
	router->is_server = 1;

	gio = g_io_channel_unix_new(router->handle);
	if (!gio) {
		secure_socket_destroy_handle(handle);
		destroy_router(router);
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

		secure_socket_destroy_handle(handle);
		destroy_router(router);
		return -EIO;
	}

	g_io_channel_unref(gio);
	return router->handle;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_client_create(const char *sock, double timeout, struct method *table)
{
	struct router *router;
	int handle;
	int status;

	handle = secure_socket_create_client(sock);
	if (handle < 0)
		return handle;

	router = create_router(sock, handle, table);
	if (!router) {
		secure_socket_destroy_handle(handle);
		return -ENOMEM;
	}

	router->timeout = timeout;
	router->is_server = 0;

	status = pthread_mutex_init(&router->packet_list_lock, NULL);
	if (status != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(status));

		secure_socket_destroy_handle(handle);
		destroy_router(router);
		return -EFAULT;
	}

	status = pthread_mutex_init(&router->route_list_lock, NULL);
	if (status != 0) {
		ErrPrint("Mutex creation failed: %s\n", strerror(status));
		secure_socket_destroy_handle(handle);
		destroy_router(router);
		return -EFAULT;
	}

	status = pthread_create(&router->info.client.thid, NULL, router_client_main, router);
	if (status != 0) {
		ErrPrint("Thread creation failed: %s\n", strerror(status));
		secure_socket_destroy_handle(handle);
		destroy_router(router);
		return -EFAULT;
	}

	(void)invoke_connected_cb(router, router->handle);
	return router->handle;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI void *com_core_packet_router_destroy(int handle)
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

	if (router->is_server) {
		if(router->info.server.accept_id > 0)
			g_source_remove(router->info.server.accept_id);

		dlist_foreach_safe(router->info.server.client_list, l, n, client) {
			router->info.server.client_list = dlist_remove(router->info.server.client_list, l);

			status = pthread_cancel(client->thid);
			if (status != 0)
				ErrPrint("Failed to cacnel a thread: %s\n", strerror(errno));

			status = pthread_join(client->thid, &ret);
			if (status != 0)
				ErrPrint("Failed to cancel a thread: %s\n", strerror(errno));

			if (ret == PTHREAD_CANCELED) {
				DbgPrint("Thread is canceled\n");
				clear_request_ctx(client->handle);
			}

			secure_socket_destroy_handle(client->handle);
			free(client);
		}
	} else {
		status = pthread_cancel(router->info.client.thid);
		if (status != 0)
			ErrPrint("Failed to cancel a thread: %s\n", strerror(errno));

		status = pthread_join(router->info.client.thid, &ret);
		if (status != 0)
			ErrPrint("Failed to join a thread: %s\n", strerror(errno));

		if (ret == PTHREAD_CANCELED) {
			DbgPrint("Thread is canceled\n");
			clear_request_ctx(router->handle);
		}
	}

	dlist_foreach_safe(router->route_list, l, n, route) {
		router->route_list = dlist_remove(router->route_list, l);
		free(route);
	}

	data = router->data;

	secure_socket_destroy_handle(router->handle);

	destroy_router(router);

	return data;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data)
{
	int ret;
	struct request_ctx *ctx;

	if (packet_type(packet) != PACKET_REQ) {
		ErrPrint("Invalid packet - should be PACKET_REQ\n");
		return -EINVAL;
	}

	ctx = create_request_ctx(handle);
	if (!ctx)
		return -ENOMEM;

	ctx->recv_cb = recv_cb;
	ctx->data = data;
	ctx->packet = packet_ref(packet);

	ret = com_core_send(handle, (void *)packet_data(packet), packet_size(packet), timeout);
	if (ret != packet_size(packet)) {
		ErrPrint("Send failed. %d <> %d (handle: %d)\n", ret, packet_size(packet), handle);
		destroy_request_ctx(ctx);
		return -EIO;
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_send_only(int handle, struct packet *packet)
{
	return com_core_packet_send_only(handle, packet);
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
EAPI int com_core_packet_router_add_link(int handle, int from, int to)
{
	struct router *router;
	struct route *route;
	int status;

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

	route->from = from;
	route->to = to;

	status = pthread_mutex_lock(&router->route_list_lock);
	if (status != 0)
		ErrPrint("Failed to lock: %s\n", strerror(status));

	router->route_list = dlist_append(router->route_list, route);

	status = pthread_mutex_unlock(&router->route_list_lock);
	if (status != 0)
		ErrPrint("Failed to unlock: %s\n", strerror(status));

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_del_link_by_from(int handle, int from)
{
	struct router *router;
	struct route *route;
	struct dlist *l;
	struct dlist *n;
	int status;

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Router is not exists\n");
		return -ENOENT;
	}

	status = pthread_mutex_lock(&router->route_list_lock);
	if (status != 0)
		ErrPrint("Failed to lock: %s\n", strerror(status));

	dlist_foreach_safe(router->route_list, l, n, route) {
		if (route->from != from)
			continue;

		router->route_list = dlist_remove(router->route_list, l);

		DbgPrint("Delete an entry from the table (%d <-> %d)\n", route->from, route->to);
		free(route);
	}

	status = pthread_mutex_unlock(&router->route_list_lock);
	if (status != 0)
		ErrPrint("Failed to unlock: %s\n", strerror(status));

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_packet_router_del_link_by_to(int handle, int to)
{
	struct router *router;
	struct route *route;
	struct dlist *l;
	struct dlist *n;
	int status;

	router = find_router_by_handle(handle);
	if (!router) {
		ErrPrint("Router is not exists\n");
		return -ENOENT;
	}

	status = pthread_mutex_lock(&router->route_list_lock);
	if (status != 0)
		ErrPrint("Failed to lock: %s\n", strerror(status));

	dlist_foreach_safe(router->route_list, l, n, route) {
		if (route->to != to)
			continue;

		router->route_list = dlist_remove(router->route_list, l);
		DbgPrint("Delete an entry from the table (%d <-> %d)\n", route->from, route->to);
		free(route);
	}

	status = pthread_mutex_unlock(&router->route_list_lock);
	if (status != 0)
		ErrPrint("Failed to unlock: %s\n", strerror(status));

	return 0;
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
