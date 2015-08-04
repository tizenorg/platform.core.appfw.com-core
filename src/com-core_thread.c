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
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <glib.h>

#include <dlog.h>

#include "dlist.h"
#include "secure_socket.h"
#include "debug.h"
#include "com-core.h"
#include "com-core_internal.h"
#include "util.h"

int errno;
#define EVENT_READY 'a'
#define EVENT_TERM 'e'

static struct {
	struct dlist *tcb_list;
	struct dlist *server_list;
} s_info = {
	.tcb_list = NULL,
	.server_list = NULL,
};

/*!
 * \brief Representing the Server Object
 */
struct server {
	int (*service_cb)(int fd, void *data);
	void *data;

	guint id;
	int handle;
};

/*!
 * \brief This is used to holds a packet
 */
struct chunk {
	char *data;
	int offset;
	int size;
	pid_t pid;
	int fd;
};

/*!
 * \brief Thread Control Block
 */
struct tcb {
	pthread_t thid;
	int handle;
	struct dlist *chunk_list;
	int evt_pipe[PIPE_MAX];
	int ctrl_pipe[PIPE_MAX];
	pthread_mutex_t chunk_lock;
	guint id; /*!< g_io_watch */

	int server_handle;

	int (*service_cb)(int fd, void *data);
	void *data;
};

static ssize_t write_safe(int fd, const void *data, size_t bufsz)
{
	int ret;
	int again;

	do {
		again = 0;
		ret = write(fd, data, bufsz);
		if (ret < 0) {
			ret = -errno;
			switch (ret) {
			case -EAGAIN:
			case -EINTR:
				again = 1;
				ErrPrint("Interrupted[%d] Again[%d]\n", fd, -ret);
				break;
			default:
				ErrPrint("Failed to write: %s (%d)\n", strerror(-ret), -ret);
				return ret;
			}
		}
	} while (again);

	return ret;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void server_destroy(struct server *server)
{
	dlist_remove_data(s_info.server_list, server);

	if (server->id > 0) {
		g_source_remove(server->id);
	}

	if (server->handle > 0) {
		secure_socket_destroy_handle(server->handle);
	}

	free(server);
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline struct server *server_create(int handle, int (*service_cb)(int fd, void *data), void *data)
{
	struct server *server;

	server = malloc(sizeof(*server));
	if (!server) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	server->handle = handle;
	server->service_cb = service_cb;
	server->data = data;

	s_info.server_list = dlist_append(s_info.server_list, server);
	return server;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void destroy_chunk(struct chunk *chunk)
{
	free(chunk->data);
	free(chunk);
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void terminate_thread(struct tcb *tcb)
{
	int status;
	struct dlist *l;
	struct dlist *n;
	void *res = NULL;
	struct chunk *chunk;

	if (write_safe(tcb->ctrl_pipe[PIPE_WRITE], &tcb, sizeof(tcb)) != sizeof(tcb)) {
		ErrPrint("Unable to write CTRL pipe (%d)\n", sizeof(tcb));
	}

	secure_socket_destroy_handle(tcb->handle);

	status = pthread_join(tcb->thid, &res);
	if (status != 0) {
		ErrPrint("Join: %s\n", strerror(status));
	} else {
		ErrPrint("Thread returns: %d\n", (int)((long)res));
	}

	dlist_foreach_safe(tcb->chunk_list, l, n, chunk) {
		/*!
		 * Discarding all packets
		 */
		DbgPrint("Discarding chunks\n");
		tcb->chunk_list = dlist_remove(tcb->chunk_list, l);
		destroy_chunk(chunk);
	}
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void chunk_remove(struct tcb *tcb, struct chunk *chunk)
{
	char event_ch;

	/* Consuming the event */
	if (read(tcb->evt_pipe[PIPE_READ], &event_ch, sizeof(event_ch)) != sizeof(event_ch)) {
		ErrPrint("Failed to get readsize\n");
		return;
	}

	CRITICAL_SECTION_BEGIN(&tcb->chunk_lock);

	dlist_remove_data(tcb->chunk_list, chunk);

	CRITICAL_SECTION_END(&tcb->chunk_lock);

	destroy_chunk(chunk);
}

/*!
 * \NOTE
 * Running thread: Other
 */
static inline int chunk_append(struct tcb *tcb, struct chunk *chunk)
{
	char event_ch = EVENT_READY;
	int ret;

	CRITICAL_SECTION_BEGIN(&tcb->chunk_lock);

	tcb->chunk_list = dlist_append(tcb->chunk_list, chunk);

	CRITICAL_SECTION_END(&tcb->chunk_lock);

	ret = write_safe(tcb->evt_pipe[PIPE_WRITE], &event_ch, sizeof(event_ch));
	if (ret < 0) {
		CRITICAL_SECTION_BEGIN(&tcb->chunk_lock);

		dlist_remove_data(tcb->chunk_list, chunk);

		CRITICAL_SECTION_END(&tcb->chunk_lock);
		return ret;
	}

	if (ret != sizeof(event_ch)) {
		ErrPrint("Failed to trigger reader\n");
	}

	/* Take a breathe */
	pthread_yield();
	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline int wait_event(struct tcb *tcb, double timeout)
{
	fd_set set;
	int ret;

	FD_ZERO(&set);
	FD_SET(tcb->evt_pipe[PIPE_READ], &set);

	if (timeout > 0.0f) {
		struct timeval tv;
		tv.tv_sec = (unsigned long)timeout;
		tv.tv_usec = (timeout - (unsigned long)timeout) * 1000000u;
		ret = select(tcb->evt_pipe[PIPE_READ] + 1, &set, NULL, NULL, &tv);
	} else if (timeout == 0.0f) {
		ret = select(tcb->evt_pipe[PIPE_READ] + 1, &set, NULL, NULL, NULL);
	} else {
		ErrPrint("Invalid timeout: %lf (it must be greater than 0.0)\n", timeout);
		return -EINVAL;
	}

	if (ret < 0) {
		ret = -errno;
		if (errno == EINTR) {
			DbgPrint("Select receives INTR\n");
			return -EAGAIN;
		}

		ErrPrint("Error: %s\n", strerror(errno));
		return ret;
	} else if (ret == 0) {
		ErrPrint("Timeout expired\n");
		return -ETIMEDOUT;
	}

	if (!FD_ISSET(tcb->evt_pipe[PIPE_READ], &set)) {
		ErrPrint("Unexpected handle is toggled\n");
		return -EINVAL;
	}

	return 0;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline struct chunk *create_chunk(int size)
{
	struct chunk *chunk;

	chunk = malloc(sizeof(*chunk));
	if (!chunk) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return NULL;
	}

	chunk->data = malloc(size);
	if (!chunk->data) {
		ErrPrint("Heap: %s\n", strerror(errno));
		free(chunk);
		return NULL;
	}

	chunk->pid = (pid_t)-1;
	chunk->size = size;
	chunk->offset = 0;
	chunk->fd = -1;
	return chunk;
}

/*!
 * \NOTE
 * Running thread: Other
 */
static void *client_cb(void *data)
{
	struct tcb *tcb = data;
	struct chunk *chunk;
	int ret = 0;
	fd_set set;
	int readsize;
	char event_ch;
	int fd;

	DbgPrint("Thread is created for %d (server: %d)\n", tcb->handle, tcb->server_handle);
	/*!
	 * \NOTE
	 * Read all data from the socket as possible as it can do
	 */
	while (1) {
		FD_ZERO(&set);
		FD_SET(tcb->handle, &set);
		FD_SET(tcb->ctrl_pipe[PIPE_READ], &set);

		fd = tcb->handle > tcb->ctrl_pipe[PIPE_READ] ? tcb->handle : tcb->ctrl_pipe[PIPE_READ];

		ret = select(fd + 1, &set, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR) {
				DbgPrint("Select receives INTR\n");
				continue;
			}
			ret = -errno;
			/*!< Error */
			ErrPrint("Error: %s\n", strerror(errno));
			break;
		} else if (ret == 0) {
			ErrPrint("What happens? [%d]\n", tcb->handle);
			continue;
		}

		if (FD_ISSET(tcb->ctrl_pipe[PIPE_READ], &set)) {
			DbgPrint("Thread is canceled\n");
			ret = -ECANCELED;
			break;
		}

		if (!FD_ISSET(tcb->handle, &set)) {
			ErrPrint("Unexpected handle is toggled\n");
			ret = -EINVAL;
			break;
		}

		readsize = 0;
		ret = ioctl(tcb->handle, FIONREAD, &readsize);
		if (ret < 0) {
			ErrPrint("ioctl: %s\n", strerror(errno));
			break;
		}

		if (readsize <= 0) {
			ErrPrint("Available data: %d\n", readsize);
			ret = -ECONNRESET;
			break;
		}

		chunk = create_chunk(readsize);
		if (!chunk) {
			ErrPrint("Failed to create a new chunk: %d\n", readsize);
			ret = -ENOMEM;
			break;
		}

		ret = secure_socket_recv_with_fd(tcb->handle, chunk->data, chunk->size, &chunk->pid, &chunk->fd);
		if (ret <= 0) {
			destroy_chunk(chunk);
			if (ret == -EAGAIN) {
				DbgPrint("Retry to get data\n");
				continue;
			}

			DbgPrint("Recv returns: %d\n", ret);
			break;
		}

		/* Update chunk size */
		chunk->size = ret;

		/*!
		 * Count of chunk elements are same with PIPE'd data
		 */
		if (chunk_append(tcb, chunk) < 0) {
			destroy_chunk(chunk);
			break;
		}
	}

	DbgPrint("Client CB is terminated (%d)\n", tcb->handle);
	/* Wake up main thread to get disconnected event */
	event_ch = EVENT_TERM;

	if (write_safe(tcb->evt_pipe[PIPE_WRITE], &event_ch, sizeof(event_ch)) != sizeof(event_ch)) {
		ErrPrint("%d byte is not written\n", sizeof(event_ch));
	}

	return (void *)(unsigned long)ret;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline void tcb_destroy(struct tcb *tcb)
{
	int status;

	dlist_remove_data(s_info.tcb_list, tcb);

	if (tcb->id > 0) {
		g_source_remove(tcb->id);
	}

	CLOSE_PIPE(tcb->evt_pipe);
	CLOSE_PIPE(tcb->ctrl_pipe);

	status = pthread_mutex_destroy(&tcb->chunk_lock);
	if (status != 0) {
		ErrPrint("Failed to destroy mutex: %s\n", strerror(status));
	}

	free(tcb);
}

/*!
 * \NOTE
 * Running thread: Main
 */
static gboolean evt_pipe_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	int pipe_read;
	struct tcb *tcb = data;
	int ret;

	pipe_read = g_io_channel_unix_get_fd(src);

	if (tcb->evt_pipe[PIPE_READ] != pipe_read) {
		ErrPrint("Closed handle (%d <> %d)\n", tcb->evt_pipe[PIPE_READ], pipe_read);
		goto errout;
	}

	if (!(cond & G_IO_IN)) {
		ErrPrint("PIPE is not valid\n");
		goto errout;
	}

	if ((cond & G_IO_ERR) || (cond & G_IO_HUP) || (cond & G_IO_NVAL)) {
		ErrPrint("PIPE is not valid\n");
		goto errout;
	}

	ret = tcb->service_cb(tcb->handle, tcb->data);
	if (ret < 0) {
		DbgPrint("Service callback returns %d < 0\n", ret);
		goto errout;
	}

	return TRUE;

errout:
	DbgPrint("Disconnecting\n");
	(void)invoke_disconn_cb_list(tcb->handle, 0, 0, 0);
	terminate_thread(tcb);
	tcb_destroy(tcb);
	return FALSE;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline struct tcb *tcb_create(int client_fd, int is_sync, int (*service_cb)(int fd, void *data), void *data)
{
	struct tcb *tcb;
	int status;

	tcb = malloc(sizeof(*tcb));
	if (!tcb) {
		ErrPrint("Error: %s\n", strerror(errno));
		return NULL;
	}

	tcb->handle = client_fd;
	tcb->chunk_list = NULL;
	tcb->service_cb = service_cb;
	tcb->data = data;
	tcb->id = 0;

	status = pthread_mutex_init(&tcb->chunk_lock, NULL);
	if (status != 0) {
		ErrPrint("Error: %s\n", strerror(status));
		free(tcb);
		return NULL;
	}

	if (pipe2(tcb->evt_pipe, O_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
		status = pthread_mutex_destroy(&tcb->chunk_lock);
		if (status != 0) {
			ErrPrint("Error: %s\n", strerror(status));
		}
		free(tcb);
		return NULL;
	}

	if (pipe2(tcb->ctrl_pipe, O_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));

		CLOSE_PIPE(tcb->evt_pipe);

		status = pthread_mutex_destroy(&tcb->chunk_lock);
		if (status != 0) {
			ErrPrint("Error: %s\n", strerror(status));
		}

		free(tcb);
		return NULL;
	}

	DbgPrint("[%d] New TCB created: R(%d), W(%d)\n", client_fd, tcb->evt_pipe[PIPE_READ], tcb->evt_pipe[PIPE_WRITE]);
	return tcb;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static gboolean accept_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	int socket_fd;
	int fd;
	int ret;
	struct tcb *tcb;
	GIOChannel *gio;
	struct server *server = data;
	pthread_attr_t attr;
	pthread_attr_t *pattr = NULL;

	socket_fd = g_io_channel_unix_get_fd(src);
	if (!(cond & G_IO_IN)) {
		ErrPrint("Accept socket closed\n");
		server_destroy(server);
		return FALSE;
	}

	if ((cond & G_IO_ERR) || (cond & G_IO_HUP) || (cond & G_IO_NVAL)) {
		DbgPrint("Socket connection is lost\n");
		server_destroy(server);
		return FALSE;
	}

	fd = secure_socket_get_connection_handle(socket_fd);
	if (fd < 0) {
		ErrPrint("Failed to get client fd from socket\n");
		server_destroy(server);
		return FALSE;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	tcb = tcb_create(fd, 0, server->service_cb, server->data);
	if (!tcb) {
		ErrPrint("Failed to create a TCB\n");
		secure_socket_destroy_handle(fd);
		server_destroy(server);
		return FALSE;
	}

	tcb->server_handle = socket_fd;

	s_info.tcb_list = dlist_append(s_info.tcb_list, tcb);

	gio = g_io_channel_unix_new(tcb->evt_pipe[PIPE_READ]);
	if (!gio) {
		ErrPrint("Failed to get gio\n");
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		server_destroy(server);
		return FALSE;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	tcb->id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)evt_pipe_cb, tcb);
	if (tcb->id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO Watch\n");
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		server_destroy(server);
		return FALSE;
	}
	g_io_channel_unref(gio);

	invoke_con_cb_list(tcb->handle, tcb->handle, 0, NULL, 0);

	ret = pthread_attr_init(&attr);
	if (ret == 0) {
		pattr = &attr;

		ret = pthread_attr_setscope(pattr, PTHREAD_SCOPE_SYSTEM);
		if (ret != 0) {
			ErrPrint("setscope: %s\n", strerror(ret));
		}

		ret = pthread_attr_setinheritsched(pattr, PTHREAD_EXPLICIT_SCHED);
		if (ret != 0) {
			ErrPrint("setinheritsched: %s\n", strerror(ret));
		}
	} else {
		ErrPrint("attr_init: %s\n", strerror(ret));
	}
	ret = pthread_create(&tcb->thid, pattr, client_cb, tcb);
	if (pattr) {
		pthread_attr_destroy(pattr);
	}
	if (ret != 0) {
		ErrPrint("Thread creation failed: %s\n", strerror(ret));
		(void)invoke_disconn_cb_list(tcb->handle, 0, 0, 0);
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		server_destroy(server);
		return FALSE;
	}

	return TRUE;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_thread_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data)
{
	GIOChannel *gio;
	int client_fd;
	struct tcb *tcb;
	int ret;
	pthread_attr_t attr;
	pthread_attr_t *pattr = NULL;

	client_fd = secure_socket_create_client(addr);
	if (client_fd < 0) {
		return client_fd;
	}

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	tcb = tcb_create(client_fd, is_sync, service_cb, data);
	if (!tcb) {
		ErrPrint("Failed to create a new TCB\n");
		secure_socket_destroy_handle(client_fd);
		return -EFAULT;
	}

	tcb->server_handle = -1;

	s_info.tcb_list = dlist_append(s_info.tcb_list, tcb);

	gio = g_io_channel_unix_new(tcb->evt_pipe[PIPE_READ]);
	if (!gio) {
		ErrPrint("Failed to get gio\n");
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	tcb->id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)evt_pipe_cb, tcb);
	if (tcb->id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO Watch\n");
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		return -EIO;
	}

	g_io_channel_unref(gio);

	invoke_con_cb_list(tcb->handle, tcb->handle, 0, NULL, 0);

	ret = pthread_attr_init(&attr);
	if (ret == 0) {
		pattr = &attr;

		ret = pthread_attr_setscope(pattr, PTHREAD_SCOPE_SYSTEM);
		if (ret != 0) {
			ErrPrint("setscope: %s\n", strerror(ret));
		}

		ret = pthread_attr_setinheritsched(pattr, PTHREAD_EXPLICIT_SCHED);
		if (ret != 0) {
			ErrPrint("setinheritsched: %s\n", strerror(ret));
		}
	} else {
		ErrPrint("attr_init: %s\n", strerror(ret));
	}
	ret = pthread_create(&tcb->thid, pattr, client_cb, tcb);
	if (pattr) {
		pthread_attr_destroy(pattr);
	}
	if (ret != 0) {
		ErrPrint("Thread creation failed: %s\n", strerror(ret));
		(void)invoke_disconn_cb_list(tcb->handle, 0, 0, 0);
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		return -EFAULT;
	}

	return tcb->handle;
}

static int validate_handle(int fd)
{
	int error;
	socklen_t len;

	len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
		ErrPrint("getsockopt: %s\n", strerror(errno));
		return 0;
	}

	return !(error == EBADF);
}

EAPI int com_core_thread_client_create_by_fd(int client_fd, int is_sync, int (*service_cb)(int fd, void *data), void *data)
{
	GIOChannel *gio;
	struct tcb *tcb;
	int ret;
	pthread_attr_t attr;
	pthread_attr_t *pattr = NULL;

	if (!validate_handle(client_fd)) {
		ErrPrint("Invalid handle: %d\n", client_fd);
		return -EINVAL;
	}

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s (%d)\n", strerror(errno), client_fd);
	}

	if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s (%d)\n", strerror(errno), client_fd);
	}

	tcb = tcb_create(client_fd, is_sync, service_cb, data);
	if (!tcb) {
		ErrPrint("Failed to create a new TCB\n");
		secure_socket_destroy_handle(client_fd);
		return -EFAULT;
	}

	tcb->server_handle = -1;

	s_info.tcb_list = dlist_append(s_info.tcb_list, tcb);

	gio = g_io_channel_unix_new(tcb->evt_pipe[PIPE_READ]);
	if (!gio) {
		ErrPrint("Failed to get gio\n");
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	tcb->id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)evt_pipe_cb, tcb);
	if (tcb->id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO Watch\n");
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		return -EIO;
	}

	g_io_channel_unref(gio);

	invoke_con_cb_list(tcb->handle, tcb->handle, 0, NULL, 0);

	ret = pthread_attr_init(&attr);
	if (ret == 0) {
		pattr = &attr;

		ret = pthread_attr_setscope(pattr, PTHREAD_SCOPE_SYSTEM);
		if (ret != 0) {
			ErrPrint("setscope: %s\n", strerror(ret));
		}

		ret = pthread_attr_setinheritsched(pattr, PTHREAD_EXPLICIT_SCHED);
		if (ret != 0) {
			ErrPrint("setinheritsched: %s\n", strerror(ret));
		}
	} else {
		ErrPrint("attr_init: %s\n", strerror(ret));
	}
	ret = pthread_create(&tcb->thid, pattr, client_cb, tcb);
	if (pattr) {
		pthread_attr_destroy(pattr);
	}
	if (ret != 0) {
		ErrPrint("Thread creation failed: %s\n", strerror(ret));
		(void)invoke_disconn_cb_list(tcb->handle, 0, 0, 0);
		secure_socket_destroy_handle(tcb->handle);
		tcb_destroy(tcb);
		return -EFAULT;
	}

	return tcb->handle;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_thread_server_create(const char *addr, int is_sync, const char *label, int (*service_cb)(int fd, void *data), void *data)
{
	GIOChannel *gio;
	int fd;
	struct server *server;

	fd = secure_socket_create_server_with_permission(addr, label);
	if (fd < 0) {
		return fd;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("fcntl: %s\n", strerror(errno));
	}

	if (!is_sync && fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("fcntl: %s\n", strerror(errno));
	}

	server = server_create(fd, service_cb, data);
	if (!server) {
		secure_socket_destroy_handle(fd);
		return -ENOMEM;
	}

	DbgPrint("Create new IO channel for socket FD: %d\n", fd);
	gio = g_io_channel_unix_new(server->handle);
	if (!gio) {
		ErrPrint("Failed to create new io channel\n");
		server_destroy(server);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	server->id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, (GIOFunc)accept_cb, server);
	if (server->id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		server_destroy(server);
		return -EIO;
	}

	g_io_channel_unref(gio);
	return server->handle;
}

/*!
 * \NOTE
 * Running thread: Main
 */
static inline struct tcb *find_tcb_by_handle(int handle)
{
	struct dlist *l;
	struct tcb *tcb;

	dlist_foreach(s_info.tcb_list, l, tcb) {
		if (tcb->handle == handle) {
			return tcb;
		}
	}

	return NULL;
}

EAPI int com_core_thread_send_with_fd(int handle, const char *buffer, int size, double timeout, int fd)
{
	int writesize;
	int ret;
	struct tcb *tcb;

	fd_set set;

	tcb = find_tcb_by_handle(handle);
	if (!tcb) {
		ErrPrint("TCB is not found\n");
		return -EINVAL;
	}

	writesize = 0;
	while (size > 0) {
		FD_ZERO(&set);
		FD_SET(tcb->handle, &set);

		if (timeout > 0.0f) {
			struct timeval tv;

			tv.tv_sec = (unsigned long)timeout;
			tv.tv_usec = (timeout - (unsigned long)timeout) * 1000000u;

			ret = select(tcb->handle + 1, NULL, &set, NULL, &tv);
		} else if (timeout == 0.0f) {
			ret = select(tcb->handle + 1, NULL, &set, NULL, NULL);
		} else {
			ErrPrint("Invalid timeout: %lf (it must be greater than 0.0)\n", timeout);
			return -EINVAL;
		}

		if (ret < 0) {
			ret = -errno;
			if (errno == EINTR) {
				DbgPrint("Select receives INTR\n");
				continue;
			}

			ErrPrint("Error: %s\n", strerror(errno));
			return ret;
		} else if (ret == 0) {
			ErrPrint("Timeout expired\n");
			break;
		}

		if (!FD_ISSET(tcb->handle, &set)) {
			ErrPrint("Unexpected handle is toggled\n");
			return -EINVAL;
		}

		ret = secure_socket_send_with_fd(tcb->handle, buffer + writesize, size, fd);
		if (ret < 0) {
			if (ret == -EAGAIN) {
				DbgPrint("Retry to send data (%d:%d)\n", writesize, size);
				continue;
			}
			DbgPrint("Failed to send: %d\n", ret);
			return ret;
		} else if (ret == 0) {
			DbgPrint("Disconnected? : Send bytes: 0\n");
			return 0;
		}

		fd = -1;    /* Send only once if it is fd */
		size -= ret;
		writesize += ret;
	}

	return writesize;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_thread_send(int handle, const char *buffer, int size, double timeout)
{
	return com_core_thread_send_with_fd(handle, buffer, size, timeout, -1);
}

EAPI int com_core_thread_recv_with_fd(int handle, char *buffer, int size, int *sender_pid, double timeout, int *fd)
{
	int readsize;
	int ret;
	struct chunk *chunk;
	struct dlist *l;
	struct tcb *tcb;
	int _sender_pid;
	int _fd;

	tcb = find_tcb_by_handle(handle);
	if (!tcb) {
		ErrPrint("TCB is not exists\n");
		return -EINVAL;
	}

	if (!sender_pid) {
		sender_pid = &_sender_pid;
	}

	if (!fd) {
		fd = &_fd;
	}

	*fd = -1;
	readsize = 0;
	while (readsize < size) {
		l = dlist_nth(tcb->chunk_list, 0);
		chunk = dlist_data(l);
		/*!
		 * \note
		 * Pumping up the pipe data
		 * This is the first time to use a chunk
		 */
		if (!chunk) {
			ret = wait_event(tcb, timeout);
			if (ret == -EAGAIN) {
				/* Log is printed from wait_event */
				continue;
			} else if (ret == -ECONNRESET) {
				DbgPrint("Connection is lost\n");
				break;
			} else if (ret < 0) {
				/* Log is printed from wait_event */
				return ret;
			}

			l = dlist_nth(tcb->chunk_list, 0);
			chunk = dlist_data(l);
			if (!chunk) {
				char event_ch;

				/* Consuming the event */
				if (read(tcb->evt_pipe[PIPE_READ], &event_ch, sizeof(event_ch)) != sizeof(event_ch)) {
					ErrPrint("Failed to get readsize: %s\n", strerror(errno));
				} else if (event_ch == EVENT_READY) {
					ErrPrint("Failed to get a new chunk\n");
				} else if (event_ch == EVENT_TERM) {
					DbgPrint("Disconnected\n");
				}

				break;
			}
		}

		ret = chunk->size - chunk->offset;
		ret = ret > (size - readsize) ? (size - readsize) : ret;
		memcpy(buffer + readsize, chunk->data + chunk->offset, ret);
		readsize += ret;
		chunk->offset += ret;

		*sender_pid = chunk->pid;
		if (chunk->fd >= 0) {
			*fd = chunk->fd;
		}

		if (chunk->offset == chunk->size) {
			chunk_remove(tcb, chunk);
		}
	}

	return readsize;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_thread_recv(int handle, char *buffer, int size, int *sender_pid, double timeout)
{
	return com_core_thread_recv_with_fd(handle, buffer, size, sender_pid, timeout, NULL);
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_thread_server_destroy(int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct tcb *tcb;
	struct server *server;

	dlist_foreach_safe(s_info.tcb_list, l, n, tcb) {
		if (tcb->server_handle != handle) {
			continue;
		}

		if (invoke_disconn_cb_list(handle, 0, 0, 0) == 0) {
			terminate_thread(tcb);
			tcb_destroy(tcb);
		}
		return 0;
	}

	dlist_foreach_safe(s_info.server_list, l, n, server) {
		if (server->handle != handle) {
			continue;
		}

		if (invoke_disconn_cb_list(handle, 0, 0, 0) == 0) {
			server_destroy(server);
		}
		return 0;
	}

	return -ENOENT;
}

/*!
 * \NOTE
 * Running thread: Main
 */
EAPI int com_core_thread_client_destroy(int handle)
{
	struct tcb *tcb;

	tcb = find_tcb_by_handle(handle);
	if (!tcb) {
		return -ENOENT;
	}

	if (invoke_disconn_cb_list(handle, 0, 0, 0) == 0) {
		terminate_thread(tcb);
		tcb_destroy(tcb);
	}
	return 0;
}

/* End of a file */
