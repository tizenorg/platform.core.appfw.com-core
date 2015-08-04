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
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
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

static struct {
	struct dlist *watch_list;
	struct dlist *conn_cb_list;
	struct dlist *disconn_cb_list;
	struct dlist *disconn_fd_list;
	enum processing_event_callback {
		PROCESSING_NONE = 0x0,
		PROCESSING_DISCONNECTION = 0x01,
		PROCESSING_CONNECTION = 0x02,
	} processing_event_callback;
} s_info = {
	.watch_list = NULL,
	.conn_cb_list = NULL,
	.disconn_cb_list = NULL,
	.disconn_fd_list = NULL,
	.processing_event_callback = PROCESSING_NONE,
};

struct watch_item {
	int server_fd;
	int fd;
	guint id;
	void *cbdata;
};

struct cbdata {
	int (*service_cb)(int fd, void *data);
	void *data;
};

struct evtdata {
	int deleted;
	int (*evt_cb)(int fd, void *data);
	void *data;
};

static int watch_item_create(int server_fd, int handle, guint id, void *cbdata)
{
	struct watch_item *item;

	item = malloc(sizeof(*item));
	if (!item) {
		return -ENOMEM;
	}

	item->server_fd = server_fd;
	item->fd = handle;
	item->id = id;
	item->cbdata = cbdata;

	DbgPrint("Watch Item is created for %d/%d\n", server_fd, handle);
	s_info.watch_list = dlist_append(s_info.watch_list, item);
	return 0;
}

static int watch_item_destroy(int handle, int remove_id, int remove_cbdata)
{
	struct dlist *l;
	struct dlist *n;
	struct watch_item *item;

	dlist_foreach_safe(s_info.watch_list, l, n, item) {
		if (item->fd == handle) {
			s_info.watch_list = dlist_remove(s_info.watch_list, l);

			DbgPrint("Watch item is destroyed for %d/%d\n", item->server_fd, item->fd);

			if (remove_id && item->id) {
				g_source_remove(item->id);
			}

			if (remove_cbdata && item->cbdata) {
				free(item->cbdata);
			}

			free(item);
			return 0;
		}
	}

	DbgPrint("No entry found\n");
	return -ENOENT;
}

static void watch_item_destroy_all(int socket_fd)
{
	struct dlist *l;
	struct dlist *n;
	struct watch_item *item;

	dlist_foreach_safe(s_info.watch_list, l, n, item) {
		if (item->server_fd == socket_fd) {
			DbgPrint("Watch item removed: %d/%d\n", item->server_fd, item->fd);
			/**
			 * @WARN
			 * If the watch_list item is removed from disconnected
			 * callback, this list loop can be broken.
			 * Please check it again.
			 */
			(void)invoke_disconn_cb_list(item->fd, 0, 0, 0);
			/**
			 * @note
			 * socket_fd will be closed by caller.
			 * so we do not need to close it at here.
			 */

			s_info.watch_list = dlist_remove(s_info.watch_list, l);
			if (item->id > 0) {
				g_source_remove(item->id);
			}
			free(item->cbdata);
			free(item);
		}
	}
}

HAPI void invoke_con_cb_list(int server_fd, int handle, guint id, void *data, int watch)
{
	struct dlist *l;
	struct dlist *n;
	struct evtdata *cbdata;

	if (watch) {
		if (watch_item_create(server_fd, handle, id, data) < 0) {
			ErrPrint("Failed to create a watch item\n");
		}
	}

	s_info.processing_event_callback |= PROCESSING_CONNECTION;
	dlist_foreach_safe(s_info.conn_cb_list, l, n, cbdata) {
		/*!
		 * \NOTE
		 * cbdata->deleted must has to be checked before call the function and
		 * return from the function call.
		 */
		if (cbdata->deleted || cbdata->evt_cb(handle, cbdata->data) < 0 || cbdata->deleted) {
			s_info.conn_cb_list = dlist_remove(s_info.conn_cb_list, l);
			free(cbdata);
		}
	}
	s_info.processing_event_callback &= ~PROCESSING_CONNECTION;
}

HAPI int invoke_disconn_cb_list(int handle, int remove_id, int remove_data, int watch)
{
	struct dlist *l;
	struct dlist *n;
	struct evtdata *cbdata;
	void *item;

	/**
	 * @note
	 * Basically, the disconnected handler will be called once.
	 * But from the disconnected callback, someone calls fini(fd),
	 * this disconnection callback can be called again.
	 * So we have to check whether this is a nested call or not.
	 * If it is a nested call, we should not do anything anymore.
	 */
	dlist_foreach_safe(s_info.disconn_fd_list, l, n, item) {
		if (handle == (int)((long)item)) { /*!< Cast for 64 bits */
			DbgPrint("nested destroyer %d\n", handle);
			return 1;
		}
	}

	s_info.disconn_fd_list = dlist_append(s_info.disconn_fd_list, (void *)((long)handle)); /*!< Cast for 64 bits */

	s_info.processing_event_callback |= PROCESSING_DISCONNECTION;
	dlist_foreach_safe(s_info.disconn_cb_list, l, n, cbdata) {
		/**
		 * @note
		 * cbdata->deleted must has to be checked before call the function and
		 * return from the function call.
		 */
		if (cbdata->deleted || cbdata->evt_cb(handle, cbdata->data) < 0 || cbdata->deleted) {
			s_info.disconn_cb_list = dlist_remove(s_info.disconn_cb_list, l);
			free(cbdata);
		}
	}
	s_info.processing_event_callback &= ~PROCESSING_DISCONNECTION;

	if (watch) {
		if (watch_item_destroy(handle, remove_id, remove_data) < 0) {
			ErrPrint("Failed to destroy watch item\n");
		}
	}

	dlist_remove_data(s_info.disconn_fd_list, (void *)((long)handle)); /*!< Cast for 64 bits */
	return 0;
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

static gboolean client_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	int client_fd;
	struct cbdata *cbdata = data;
	int ret;

	client_fd = g_io_channel_unix_get_fd(src);

	if (!(cond & G_IO_IN)) {
		DbgPrint("Client is disconencted\n");
		(void)invoke_disconn_cb_list(client_fd, 0, 1, 1);
		secure_socket_destroy_handle(client_fd);
		return FALSE;
	}

	if ((cond & G_IO_ERR) || (cond & G_IO_HUP) || (cond & G_IO_NVAL)) {
		DbgPrint("Client connection is lost\n");
		(void)invoke_disconn_cb_list(client_fd, 0, 1, 1);
		secure_socket_destroy_handle(client_fd);
		return FALSE;
	}

	ret = cbdata->service_cb(client_fd, cbdata->data);
	if (ret < 0) {
		DbgPrint("service callback returns %d < 0\n", ret);
		(void)invoke_disconn_cb_list(client_fd, 0, 1, 1);
		secure_socket_destroy_handle(client_fd);
		return FALSE;
	}

	/* Check whether the socket FD is closed or not */
	if (!validate_handle(client_fd)) {
		(void)invoke_disconn_cb_list(client_fd, 0, 1, 1);
		secure_socket_destroy_handle(client_fd);
		return FALSE;
	}

	return TRUE;
}

static gboolean accept_cb(GIOChannel *src, GIOCondition cond, gpointer cbdata)
{
	int socket_fd;
	int client_fd;
	GIOChannel *gio;
	guint id;

	socket_fd = g_io_channel_unix_get_fd(src);
	if (!(cond & G_IO_IN)) {
		ErrPrint("Accept socket closed\n");
		watch_item_destroy_all(socket_fd);
		secure_socket_destroy_handle(socket_fd);
		free(cbdata);
		return FALSE;
	}

	if ((cond & G_IO_ERR) || (cond & G_IO_HUP) || (cond & G_IO_NVAL)) {
		ErrPrint("Client connection is lost\n");
		watch_item_destroy_all(socket_fd);
		secure_socket_destroy_handle(socket_fd);
		free(cbdata);
		return FALSE;
	}

	client_fd = secure_socket_get_connection_handle(socket_fd);
	if (client_fd < 0) {
		/* Keep server running */
		return TRUE;
	}
	DbgPrint("New connectino arrived: server(%d), client(%d)\n", socket_fd, client_fd);

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	gio = g_io_channel_unix_new(client_fd);
	if (!gio) {
		ErrPrint("Failed to get gio\n");
		secure_socket_destroy_handle(client_fd);
		/* Keep server running */
		return TRUE;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)client_cb, cbdata);
	if (id == 0) {
		GError *err = NULL;

		ErrPrint("Failed to add IO watch\n");
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(client_fd);
		/* Keep server running */
		return TRUE;
	}

	g_io_channel_unref(gio);

	invoke_con_cb_list(socket_fd, client_fd, id, NULL, 1);

	if (!validate_handle(socket_fd)) {
		watch_item_destroy_all(socket_fd);
		return FALSE;
	}

	/* Keep server running */
	return TRUE;
}

EAPI int com_core_server_create(const char *addr, int is_sync, const char *label, int (*service_cb)(int fd, void *data), void *data)
{
	GIOChannel *gio;
	guint id;
	int fd;
	struct cbdata *cbdata;

	cbdata = malloc(sizeof(*cbdata));
	if (!cbdata) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return -ENOMEM;
	}

	cbdata->service_cb = service_cb;
	cbdata->data = data;

	fd = secure_socket_create_server_with_permission(addr, label);
	if (fd < 0) {
		free(cbdata);
		return fd;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("fcntl: %s\n", strerror(errno));
	}

	if (!is_sync && fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("fcntl: %s\n", strerror(errno));
	}

	DbgPrint("Create new IO channel for server FD: %d\n", fd);
	gio = g_io_channel_unix_new(fd);
	if (!gio) {
		ErrPrint("Failed to create new io channel\n");
		free(cbdata);
		secure_socket_destroy_handle(fd);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, (GIOFunc)accept_cb, cbdata);
	if (id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		free(cbdata);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(fd);
		return -EIO;
	}

	if (watch_item_create(fd, fd, id, cbdata) < 0) {
		GError *err = NULL;

		ErrPrint("Failed to create a watch item\n");
		g_source_remove(id);

		free(cbdata);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(fd);
		return -ENOMEM;
	}

	g_io_channel_unref(gio);
	return fd;
}

EAPI int com_core_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data)
{
	GIOChannel *gio;
	guint id;
	int client_fd;
	struct cbdata *cbdata;

	cbdata = malloc(sizeof(*cbdata));
	if (!cbdata) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return -ENOMEM;
	}

	cbdata->service_cb = service_cb;
	cbdata->data = data;

	client_fd = secure_socket_create_client(addr);
	if (client_fd < 0) {
		free(cbdata);
		return client_fd;
	}

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (!is_sync && fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	gio = g_io_channel_unix_new(client_fd);
	if (!gio) {
		ErrPrint("Failed to create a new IO channel\n");
		free(cbdata);
		secure_socket_destroy_handle(client_fd);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)client_cb, cbdata);
	if (id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		free(cbdata);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(client_fd);
		return -EIO;
	}

	g_io_channel_unref(gio);

	invoke_con_cb_list(client_fd, client_fd, id, cbdata, 1);
	return client_fd;
}

EAPI int com_core_client_create_by_fd(int client_fd, int is_sync, int (*service_cb)(int fd, void *data), void *data)
{
	GIOChannel *gio;
	guint id;
	struct cbdata *cbdata;

	if (!validate_handle(client_fd)) {
		ErrPrint("Invalid handle: %d\n", client_fd);
		return -EINVAL;
	}

	cbdata = malloc(sizeof(*cbdata));
	if (!cbdata) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return -ENOMEM;
	}

	cbdata->service_cb = service_cb;
	cbdata->data = data;

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	if (!is_sync && fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
		ErrPrint("Error: %s\n", strerror(errno));
	}

	gio = g_io_channel_unix_new(client_fd);
	if (!gio) {
		ErrPrint("Failed to create a new IO channel\n");
		free(cbdata);
		secure_socket_destroy_handle(client_fd);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(gio, FALSE);

	id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)client_cb, cbdata);
	if (id == 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		free(cbdata);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		g_io_channel_unref(gio);
		secure_socket_destroy_handle(client_fd);
		return -EIO;
	}

	g_io_channel_unref(gio);

	invoke_con_cb_list(client_fd, client_fd, id, cbdata, 1);
	return client_fd;
}

EAPI int com_core_add_event_callback(enum com_core_event_type type, int (*evt_cb)(int handle, void *data), void *data)
{
	struct evtdata *cbdata;
	cbdata = malloc(sizeof(*cbdata));
	if (!cbdata) {
		ErrPrint("Heap: %s\n", strerror(errno));
		return -ENOMEM;
	}

	cbdata->evt_cb = evt_cb;
	cbdata->data = data;
	cbdata->deleted = 0;

	if (type == CONNECTOR_CONNECTED) {
		s_info.conn_cb_list = dlist_append(s_info.conn_cb_list, cbdata);
	} else {
		s_info.disconn_cb_list = dlist_append(s_info.disconn_cb_list, cbdata);
	}
	return 0;
}

EAPI int com_core_recv_with_fd(int handle, char *buffer, int size, int *sender_pid, double timeout, int *fd)
{
	int readsize;
	int ret;
	int *recv_fd;

	fd_set set;

	recv_fd = fd;
	readsize = 0;
	while (size > 0) {
		FD_ZERO(&set);
		FD_SET(handle, &set);

		if (timeout > 0.0f) {
			struct timeval tv;

			tv.tv_sec = (unsigned long)timeout;
			tv.tv_usec = (timeout - (unsigned long)timeout) * 1000000u;
			ret = select(handle + 1, &set, NULL, NULL, &tv);
		} else if (timeout == 0.0f) {
			ret = select(handle + 1, &set, NULL, NULL, NULL);
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

		if (!FD_ISSET(handle, &set)) {
			ErrPrint("Unexpected handle is toggled\n");
			return -EINVAL;
		}

		ret = secure_socket_recv_with_fd(handle, buffer + readsize, size, sender_pid, recv_fd);
		if (ret < 0) {
			if (ret == -EAGAIN) {
				DbgPrint("Retry to get data (%d:%d)\n", readsize, size);
				continue;
			}
			DbgPrint("[%d] recv returns: %d\n", handle, ret);
			return ret;
		} else if (ret == 0) {
			DbgPrint("Disconnected(req.size: %d)\n", size);
			return 0;
		}

		recv_fd = NULL; /** Get it only for the first time */
		size -= ret;
		readsize += ret;
	}

	return readsize;
}

EAPI int com_core_recv(int handle, char *buffer, int size, int *sender_pid, double timeout)
{
	return com_core_recv_with_fd(handle, buffer, size, sender_pid, timeout, NULL);
}

EAPI int com_core_send_with_fd(int handle, const char *buffer, int size, double timeout, int fd)
{
	int writesize;
	int ret;

	fd_set set;

	writesize = 0;
	while (size > 0) {

		FD_ZERO(&set);
		FD_SET(handle, &set);

		if (timeout > 0.0f) {
			struct timeval tv;

			tv.tv_sec = (unsigned long)timeout;
			tv.tv_usec = (timeout - (unsigned long)timeout) * 1000000u;

			ret = select(handle + 1, NULL, &set, NULL, &tv);
		} else if (timeout == 0.0f) {
			ret = select(handle + 1, NULL, &set, NULL, NULL);
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

		if (!FD_ISSET(handle, &set)) {
			ErrPrint("Unexpected handle is toggled\n");
			return -EINVAL;
		}

		ret = secure_socket_send_with_fd(handle, buffer + writesize, size, fd);
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

		fd = -1; /** Send only once if it is fd */
		size -= ret;
		writesize += ret;
	}

	return writesize;
}

EAPI int com_core_send(int handle, const char *buffer, int size, double timeout)
{
	return com_core_send_with_fd(handle, buffer, size, timeout, -1);
}

EAPI void *com_core_del_event_callback(enum com_core_event_type type, int (*cb)(int handle, void *data), void *data)
{
	struct dlist *l;
	struct dlist *n;
	struct evtdata *cbdata;

	if (type == CONNECTOR_CONNECTED) {
		dlist_foreach_safe(s_info.conn_cb_list, l, n, cbdata) {
			if (cbdata->evt_cb == cb && cbdata->data == data) {
				void *data;
				data = cbdata->data;

				if ((s_info.processing_event_callback & PROCESSING_CONNECTION) == PROCESSING_CONNECTION) {
					cbdata->deleted = 1;
				} else {
					dlist_remove_data(s_info.conn_cb_list, cbdata);
					free(cbdata);
				}

				return data;
			}
		}
	} else {
		dlist_foreach_safe(s_info.disconn_cb_list, l, n, cbdata) {
			if (cbdata->evt_cb == cb && cbdata->data == data) {
				void *data;
				data = cbdata->data;

				if ((s_info.processing_event_callback & PROCESSING_DISCONNECTION) == PROCESSING_DISCONNECTION) {
					cbdata->deleted = 1;
				} else {
					dlist_remove_data(s_info.disconn_cb_list, cbdata);
					free(cbdata);
				}
				return data;
			}
		}
	}

	return NULL;
}

EAPI int com_core_server_destroy(int handle)
{
	DbgPrint("Close server handle[%d]\n", handle);
	if (invoke_disconn_cb_list(handle, 1, 1, 1) == 0) {
		secure_socket_destroy_handle(handle);
	}
	return 0;
}

EAPI int com_core_client_destroy(int handle)
{
	DbgPrint("Close client handle[%d]\n", handle);
	if (invoke_disconn_cb_list(handle, 1, 1, 1) == 0) {
		secure_socket_destroy_handle(handle);
	}
	return 0;
}

/* End of a file */
