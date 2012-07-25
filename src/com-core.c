#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <glib.h>

#include <dlog.h>

#include "dlist.h"
#include "secure_socket.h"
#include "packet.h"
#include "debug.h"
#include "com-core.h"
#include "util.h"

static struct {
	struct dlist *conn_cb_list;
	struct dlist *disconn_cb_list;
} s_info = {
	.conn_cb_list = NULL,
	.disconn_cb_list = NULL,
};

struct cbdata {
	int (*service_cb)(int fd, int readsize, void *data);
	void *data;
};

struct evtdata {
	int (*evt_cb)(int fd, void *data);
	void *data;
};

static inline void invoke_con_cb_list(int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct evtdata *cbdata;

	dlist_foreach_safe(s_info.conn_cb_list, l, n, cbdata) {
		if (cbdata->evt_cb(handle, cbdata->data) < 0) {
			s_info.conn_cb_list = dlist_remove(s_info.conn_cb_list, l);
			free(cbdata);
		}
	}
}

static inline void invoke_disconn_cb_list(int handle)
{
	struct dlist *l;
	struct dlist *n;
	struct evtdata *cbdata;

	dlist_foreach_safe(s_info.disconn_cb_list, l, n, cbdata) {
		if (cbdata->evt_cb(handle, cbdata->data) < 0) {
			s_info.disconn_cb_list = dlist_remove(s_info.disconn_cb_list, l);
			free(cbdata);
		}
	}
}

static gboolean client_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	int client_fd;
	struct cbdata *cbdata = data;
	int ret;
	int readsize;

	client_fd = g_io_channel_unix_get_fd(src);

	if (!(cond & G_IO_IN)) {
		DbgPrint("Client is disconencted\n");
		invoke_disconn_cb_list(client_fd);
		secure_socket_remove_connection_handle(client_fd);
		return FALSE;
	}

	if (ioctl(client_fd, FIONREAD, &readsize) < 0 || readsize == 0) {
		DbgPrint("Client is disconencted (readsize: %d)\n", readsize);
		invoke_disconn_cb_list(client_fd);
		secure_socket_remove_connection_handle(client_fd);
		return FALSE;
	}

	ret = cbdata->service_cb(client_fd, readsize, cbdata->data);
	if (ret < 0) {
		DbgPrint("service callback returns < 0\n");
		invoke_disconn_cb_list(client_fd);
		secure_socket_remove_connection_handle(client_fd);
		return FALSE;
	}

	return TRUE;
}

static gboolean accept_cb(GIOChannel *src, GIOCondition cond, gpointer data)
{
	int socket_fd;
	int client_fd;
	GIOChannel *gio;
	guint id;

	socket_fd = g_io_channel_unix_get_fd(src);
	if (!(cond & G_IO_IN)) {
		ErrPrint("Accept socket closed\n");
		free(data);
		return FALSE;
	}

	client_fd = secure_socket_get_connection_handle(socket_fd);
	if (client_fd < 0) {
		free(data);
		return FALSE;
	}

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0)
		ErrPrint("Error: %s\n", strerror(errno));

	if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0)
		ErrPrint("Error: %s\n", strerror(errno));

	gio = g_io_channel_unix_new(client_fd);
	if (!gio) {
		ErrPrint("Failed to get gio\n");
		secure_socket_remove_connection_handle(client_fd);
		free(data);
		return FALSE;
	}

	id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, client_cb, data);
	if (id < 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		g_io_channel_unref(gio);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		secure_socket_remove_connection_handle(client_fd);
		free(data);
		return FALSE;
	}

	g_io_channel_unref(gio);

	invoke_con_cb_list(client_fd);
	DbgPrint("New client is connected with %d\n", client_fd);
	return TRUE;
}

EAPI int com_core_server_create(const char *addr, int is_sync, int (*service_cb)(int fd, int readsize, void *data), void *data)
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

	fd = secure_socket_create_server(addr);
	if (fd < 0) {
		free(cbdata);
		return fd;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		ErrPrint("fcntl: %s\n", strerror(errno));

	if (!is_sync) {
		if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
			ErrPrint("fcntl: %s\n", strerror(errno));
	}

	gio = g_io_channel_unix_new(fd);
	if (!gio) {
		ErrPrint("Failed to create new io channel\n");
		free(cbdata);
		close(fd);
		return -EIO;
	}

	id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL, (GIOFunc)accept_cb, cbdata);
	if (id < 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		free(cbdata);
		g_io_channel_unref(gio);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		close(fd);
		return -EIO;
	}

	g_io_channel_unref(gio);
	return fd;
}

EAPI int com_core_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, int readsize, void *data), void *data)
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

	if (fcntl(client_fd, F_SETFD, FD_CLOEXEC) < 0)
		ErrPrint("Error: %s\n", strerror(errno));

	if (!is_sync) {
		if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0)
			ErrPrint("Error: %s\n", strerror(errno));
	}

	gio = g_io_channel_unix_new(client_fd);
	if (!gio) {
		ErrPrint("Failed to create a new IO channel\n");
		free(cbdata);
		close(client_fd);
		return -EIO;
	}

	id = g_io_add_watch(gio, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc)client_cb, cbdata);
	if (id < 0) {
		GError *err = NULL;
		ErrPrint("Failed to add IO watch\n");
		free(cbdata);
		g_io_channel_unref(gio);
		g_io_channel_shutdown(gio, TRUE, &err);
		if (err) {
			ErrPrint("Shutdown: %s\n", err->message);
			g_error_free(err);
		}
		close(client_fd);
		return -EIO;
	}

	g_io_channel_unref(gio);
	invoke_con_cb_list(client_fd);
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

	if (type == CONNECTOR_CONNECTED)
		s_info.conn_cb_list = dlist_append(s_info.conn_cb_list, cbdata);
	else
		s_info.disconn_cb_list = dlist_append(s_info.disconn_cb_list, cbdata);
	return 0;
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
				dlist_remove_data(s_info.conn_cb_list, cbdata);
				free(cbdata);
				return data;
			}
		}
	} else {
		dlist_foreach_safe(s_info.disconn_cb_list, l, n, cbdata) {
			if (cbdata->evt_cb == cb && cbdata->data == data) {
				void *data;
				data = cbdata->data;
				dlist_remove_data(s_info.disconn_cb_list, cbdata);
				free(cbdata);
				return data;
			}
		}
	}

	return NULL;
}

EAPI int com_core_server_destroy(int handle)
{
	close(handle);
	return 0;
}

EAPI int com_core_client_destroy(int handle)
{
	close(handle);
	return 0;
}

/* End of a file */
