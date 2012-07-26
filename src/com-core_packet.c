#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>

#include <glib.h>
#include <dlog.h>

#include "debug.h"
#include "com-core.h"
#include "packet.h"
#include "secure_socket.h"
#include "dlist.h"
#include "com-core_packet.h"
#include "util.h"

#define DEFAULT_TIMEOUT 2

static struct info {
	struct dlist *recv_list;
	struct dlist *request_list;
	char *addr;
} s_info = {
	.recv_list = NULL,
	.request_list = NULL,
	.addr = NULL,
};

struct request_ctx {
	pid_t pid;
	int handle;

	struct packet *packet;
	int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data);
	void *data;

	guint timeout;
};

struct recv_ctx {
	enum {
		RECV_STATE_INIT,
		RECV_STATE_HEADER,
		RECV_STATE_BODY,
		RECV_STATE_READY,
	} state;
	int handle;
	int offset;
	pid_t pid;
	struct packet *packet;
};

static inline struct request_ctx *find_request_ctx(int handle, unsigned long seq)
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
	if (ctx->timeout > 0)
		g_source_remove(ctx->timeout);

	packet_unref(ctx->packet);
	dlist_remove_data(s_info.request_list, ctx);
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

	s_info.request_list = dlist_append(s_info.request_list, ctx);
	return ctx;
}

static inline struct recv_ctx *find_recv_ctx(int handle)
{
	struct recv_ctx *ctx;
	struct dlist *l;

	dlist_foreach(s_info.recv_list, l, ctx) {
		if (ctx->handle == handle)
			return ctx;
	}

	return NULL;
}

static inline void destroy_recv_ctx(struct recv_ctx *ctx)
{
	dlist_remove_data(s_info.recv_list, ctx);
	packet_destroy(ctx->packet);
	free(ctx);
}

static inline struct recv_ctx *create_recv_ctx(int handle)
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

	s_info.recv_list = dlist_append(s_info.recv_list, ctx);
	return ctx;
}

static inline void packet_ready(int handle, const struct recv_ctx *receive, struct method *table)
{
	struct request_ctx *request;
	unsigned long sequence;
	struct packet *result;
	register int i;

	/*!
	 * \note
	 * Is this ack packet?
	 */
	switch (packet_type(receive->packet)) {
	case PACKET_ACK:
		sequence = packet_seq(receive->packet);
		request = find_request_ctx(handle, sequence);
		if (!request) {
			ErrPrint("This is not requested packet (%s)\n", packet_command(receive->packet));
			break;
		}

		if (request->recv_cb)
			request->recv_cb(receive->pid, handle, receive->packet, request->data);

		destroy_request_ctx(request);
		break;
	case PACKET_REQ:
		for (i = 0; table[i].cmd; i++) {
			if (strcmp(table[i].cmd, packet_command(receive->packet)))
				continue;

			result = table[i].handler(receive->pid, handle, receive->packet);
			if (result) {
				int ret;
				ret = secure_socket_send(handle, (void *)packet_data(result), packet_size(result));
				if (ret < 0)
					ErrPrint("Failed to send an ack packet\n");
				packet_destroy(result);
			}
			break;
		}

		break;
	case PACKET_REQ_NOACK:
		for (i = 0; table[i].cmd; i++) {
			if (strcmp(table[i].cmd, packet_command(receive->packet)))
				continue;

			result = table[i].handler(receive->pid, handle, receive->packet);
			if (result)
				packet_destroy(result);
		}
		break;
	default:
		break;
	}

	return;
}

static int client_disconnected_cb(int handle, void *data)
{
	struct recv_ctx *receive;
	struct request_ctx *request;
	struct dlist *l;
	struct dlist *n;
	pid_t pid = (pid_t)-1;

	DbgPrint("Clean up all requests and a receive context\n");

	receive = find_recv_ctx(handle);
	if (receive) {
		pid = receive->pid;
		destroy_recv_ctx(receive);
	}

	dlist_foreach_safe(s_info.request_list, l, n, request) {
		if (request->handle == handle) {
			if (request->recv_cb)
				request->recv_cb(pid, handle, NULL, request->data);

			destroy_request_ctx(request);
		}
	}

	return 0;
}

static int service_cb(int handle, int readsize, void *data)
{
	struct recv_ctx *receive;
	pid_t pid;
	int ret;
	int size;
	char *ptr;

	receive = find_recv_ctx(handle);
	if (!receive)
		receive = create_recv_ctx(handle);

	if (!receive) {
		ErrPrint("Couldn't find or create a receive context\n");
		return -EIO;
	}

	while (readsize > 0) {
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
				ErrPrint("Heap: %s\n", strerror(errno));
				destroy_recv_ctx(receive);
				return -ENOMEM;
			}

			ret = secure_socket_recv(handle, ptr, size, &pid);
			if (ret < 0 || (receive->pid != -1 && receive->pid != pid)) {
				ErrPrint("Recv[%d], pid[%d :: %d]\n", ret, receive->pid, pid);
				free(ptr);
				destroy_recv_ctx(receive);
				return -EIO;
			}

			receive->pid = pid;
			receive->packet = packet_build(receive->packet, receive->offset, ptr, ret);
			free(ptr);

			if (!receive->packet) {
				ErrPrint("Built packet is not valid\n");
				destroy_recv_ctx(receive);
				return -EFAULT;
			}

			receive->offset += ret;
			readsize -= ret;
			if (receive->offset == packet_header_size()) {
				if (packet_size(receive->packet) == receive->offset)
					receive->state = RECV_STATE_READY;
				else
					receive->state = RECV_STATE_BODY;
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
				ErrPrint("Heap: %s\n", strerror(errno));
				destroy_recv_ctx(receive);
				return -ENOMEM;
			}

			ret = secure_socket_recv(handle, ptr, size, &pid);
			if (ret < 0 || receive->pid != pid) {
				ErrPrint("Recv[%d], pid[%d :: %d]\n", ret, receive->pid, pid);
				free(ptr);
				destroy_recv_ctx(receive);
				return -EIO;
			}

			receive->packet = packet_build(receive->packet, receive->offset, ptr, ret);
			free(ptr);

			if (!receive->packet) {
				destroy_recv_ctx(receive);
				return -EFAULT;
			}

			receive->offset += ret;
			readsize -= ret;
			if (receive->offset == packet_size(receive->packet))
				receive->state = RECV_STATE_READY;
			break;
		case RECV_STATE_READY:
		default:
			break;
		}

		if (receive->state == RECV_STATE_READY) {
			packet_ready(handle, receive, data);
			destroy_recv_ctx(receive);
			/*!
			 * \note
			 * Just quit from this function
			 * Even if we have read size
			 * Next time is comming soon ;)
			 */
			break;
		}
	}

	return 0;
}

static gboolean timeout_cb(gpointer data)
{
	struct request_ctx *ctx = data;

	ErrPrint("Timeout (Not responding in time)\n");

	if (ctx->recv_cb)
		ctx->recv_cb(ctx->pid, ctx->handle, NULL, ctx->data);

	ctx->timeout = 0u;
	destroy_request_ctx(ctx);
	return FALSE;
}

EAPI int com_core_packet_async_send(int handle, struct packet *packet, unsigned int timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data)
{
	int ret;
	struct request_ctx *ctx;

	ctx = create_request_ctx(handle);
	if (!ctx)
		return -ENOMEM;

	ctx->recv_cb = recv_cb;
	ctx->data = data;
	ctx->packet = packet_ref(packet);
	if (timeout > 0) {
		ctx->timeout = g_timeout_add(timeout, timeout_cb, ctx);
		if (ctx->timeout == 0)
			ErrPrint("Failed to add timeout\n");
	}

	ret = secure_socket_send(handle, (void *)packet_data(packet), packet_size(packet));
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

	ret = secure_socket_send(handle, (void *)packet_data(packet), packet_size(packet));
	if (ret != packet_size(packet))
		return -EIO;

	return 0;
}

EAPI struct packet *com_core_packet_oneshot_send(const char *addr, struct packet *packet)
{
	int ret;
	int sz;
	int fd;
	pid_t pid;
	int offset;
	struct packet *result = NULL;
	void *ptr;
	struct timeval stv;
	struct timeval etv;
	struct timeval rtv;

	fd = secure_socket_create_client(addr);
	if (fd < 0)
		return NULL;

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		ErrPrint("fcntl: %s\n", strerror(errno));

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		ErrPrint("Error: %s\n", strerror(errno));

	gettimeofday(&stv, NULL);
	sz = 0;
	do {
		ret = secure_socket_send(fd, (char *)packet_data(packet) + sz, packet_size(packet) - sz);
		if (ret < 0) {
			secure_socket_destroy(fd);
			return NULL;
		}

		sz += ret;

		gettimeofday(&etv, NULL);
		timersub(&etv, &stv, &rtv);
		if (rtv.tv_sec > DEFAULT_TIMEOUT) {
			ErrPrint("Timeout\n");
			secure_socket_destroy(fd);
			return NULL;
		}
	} while (sz < packet_size(packet));

	offset = 0;
	ptr = malloc(packet_header_size());
	if (!ptr) {
		ErrPrint("Heap: %s\n", strerror(errno));
		secure_socket_destroy(fd);
		return NULL;
	}

	gettimeofday(&stv, NULL);
	sz = 0;
	do {
		ret = secure_socket_recv(fd, (char *)ptr + sz, packet_header_size() - sz, &pid);
		if (ret < 0) {
			free(ptr);
			secure_socket_destroy(fd);
			return NULL;
		}
		sz += ret;
		gettimeofday(&etv, NULL);
		timersub(&etv, &stv, &rtv);
		if (rtv.tv_sec > DEFAULT_TIMEOUT) {
			ErrPrint("Timeout\n");
			free(ptr);
			secure_socket_destroy(fd);
			return NULL;
		}
	} while (sz < packet_header_size());
	result = packet_build(result, offset, ptr, ret);
	offset += ret;
	free(ptr);

	ptr = malloc(packet_payload_size(result));
	if (!ptr) {
		ErrPrint("Heap: %s\n", strerror(errno));
		secure_socket_destroy(fd);
		return NULL;
	}

	gettimeofday(&stv, NULL);
	sz = 0;
	do {
		ret = secure_socket_recv(fd, (char *)ptr + sz, packet_payload_size(result) - sz, &pid);
		if (ret < 0) {
			free(ptr);
			secure_socket_destroy(fd);
			return NULL;
		}
		sz += ret;
		gettimeofday(&etv, NULL);
		timersub(&etv, &stv, &rtv);
		if (rtv.tv_sec > DEFAULT_TIMEOUT) {
			ErrPrint("Timeout\n");
			free(ptr);
			secure_socket_destroy(fd);
			return NULL;
		}
	} while (sz < packet_payload_size(result));
	result = packet_build(result, offset, ptr, ret);
	offset += ret;
	free(ptr);
	secure_socket_destroy(fd);
	return result;
}

static inline int com_core_packet_init(void)
{
	return com_core_add_event_callback(CONNECTOR_DISCONNECTED, client_disconnected_cb, NULL);
}

static inline int com_core_packet_fini(void)
{
	com_core_del_event_callback(CONNECTOR_DISCONNECTED, client_disconnected_cb, NULL);
	return 0;
}

EAPI int com_core_packet_client_init(const char *addr, int is_sync, struct method *table)
{
	int ret;

	ret = com_core_packet_init();
	if (ret < 0)
		return ret;

	ret = com_core_client_create(addr, 0, service_cb, table);
	if (ret < 0)
		com_core_packet_fini();

	return ret;
}

EAPI int com_core_packet_client_fini(int handle)
{
	com_core_client_destroy(handle);
	com_core_packet_fini();
	return 0;
}

EAPI int com_core_packet_server_init(const char *addr, struct method *table)
{
	int ret;

	ret = com_core_packet_init();
	if (ret < 0)
		return ret;

	ret = com_core_server_create(addr, 0, service_cb, table);
	if (ret < 0)
		com_core_packet_fini();

	return ret;
}

EAPI int com_core_packet_server_fini(int handle)
{
	com_core_server_destroy(handle);
	com_core_packet_fini();
	return 0;
}

/* End of a file */
