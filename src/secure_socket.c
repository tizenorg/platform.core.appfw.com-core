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
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <stdlib.h>
#include <systemd/sd-daemon.h>
#include <attr/xattr.h>
#include <dlog.h>

#include "secure_socket.h"
#include "debug.h"
#include "util.h"

#define BACKLOG 	50	/*!< Accept only 50 connections as default */
#define SNDBUF_SZ	262144	/*!< 256 KB, this will be doubled by kernel */
#define RCVBUF_SZ	524288	/*!< 512 KB, this will be doubled by kernel */

enum scheme {
	SCHEME_LOCAL = 0x00,
	SCHEME_SDLOCAL = 0x01,
	SCHEME_REMOTE = 0x02,
	SCHEME_UNKNOWN = 0x03,
};

struct function_table {
	int type;
	int (*create_socket)(const char *peer, int port, struct sockaddr *addr);
	int (*setup_handle)(int handle);
};

int errno;

static inline int create_unix_socket(const char *peer, int port, struct sockaddr *addr)
{
	int len;
	int handle;
	struct sockaddr_un *un_addr = (struct sockaddr_un *)addr;

	len = sizeof(*un_addr);
	bzero(un_addr, len);

	if (strlen(peer) >= sizeof(un_addr->sun_path)) {
		ErrPrint("peer %s is too long to remember it\\n", peer);
		return -1;
	}

	/* We can believe this has no prob, because
	 * we already check the size of add.rsun_path
	 */
	strcpy(un_addr->sun_path, peer);
	un_addr->sun_family = AF_UNIX;

	handle = socket(PF_UNIX, SOCK_STREAM, 0);
	if (handle < 0) {
		handle = -errno;
		ErrPrint("Failed to create a socket %s\n", strerror(errno));
	}

	return handle;
}

static inline int create_inet_socket(const char *peer, int port, struct sockaddr *addr)
{
	int handle;
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;

	bzero(in_addr, sizeof(*in_addr));

	in_addr->sin_port = htons(port);
	in_addr->sin_family = AF_INET;
	if (*peer == '\0') {
		in_addr->sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		in_addr->sin_addr.s_addr = inet_addr(peer);
	}

	handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle < 0) {
		handle = -errno;
		ErrPrint("socket: %s\n", strerror(errno));
	}

	return handle;
}

static inline int create_systemd_socket(const char *peer, int port, struct sockaddr *addr)
{
	int handle;
	int cnt;

	cnt = sd_listen_fds(0);
	DbgPrint("Usable socket %s cnt[%d]\n", peer, cnt);

	for (handle = SD_LISTEN_FDS_START; handle < SD_LISTEN_FDS_START + cnt; ++handle) {
		if (sd_is_socket_unix(handle, SOCK_STREAM, 1, peer, 0) > 0) {
			DbgPrint("Usable socket %s was passed by SystemD under descriptor %d\n", peer, handle);
			return handle;
		}
	}

	DbgPrint("Not found socket: %s\n", peer);
	return -1;
}

static inline int setup_unix_handle(int handle)
{
	int on = 1;
	int sndbuf = SNDBUF_SZ;
	int rcvbuf = RCVBUF_SZ;

	if (setsockopt(handle, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
		int ret;
		ret = -errno;
		ErrPrint("Failed to change sock opt : %s\n", strerror(errno));
		return ret;
	}

	(void)setsockopt(handle, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	(void)setsockopt(handle, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	(void)setsockopt(handle, IPPROTO_IP, TCP_NODELAY, &on, sizeof(on));

	return 0;
}

static inline int setup_inet_handle(int handle)
{
	int on = 1;

	(void)setsockopt(handle, IPPROTO_IP, TCP_NODELAY, &on, sizeof(on));

	return 0;
}

static inline char *parse_scheme(const char *peer, int *port, struct function_table *vtable)
{
	int _port;
	char *addr = NULL;

	if (!port)
		port = &_port;

	*port = 0;

	if (!strncasecmp(peer, COM_CORE_LOCAL_SCHEME, COM_CORE_LOCAL_SCHEME_LEN)) {
		vtable->type = (int)SCHEME_LOCAL;
		peer += COM_CORE_LOCAL_SCHEME_LEN;

		addr = strdup(peer);
		if (!addr) {
			ErrPrint("Heap: %s\n", strerror(errno));
		}

		vtable->create_socket = create_unix_socket;
		vtable->setup_handle = setup_unix_handle;
	} else if (!strncasecmp(peer, COM_CORE_SD_LOCAL_SCHEME, COM_CORE_SD_LOCAL_SCHEME_LEN)) {
		vtable->type = (int)SCHEME_SDLOCAL;
		peer += COM_CORE_SD_LOCAL_SCHEME_LEN;

		addr = strdup(peer);
		if (!addr) {
			ErrPrint("Heap: %s\n", strerror(errno));
		}

		vtable->create_socket = create_systemd_socket;
		vtable->setup_handle = setup_unix_handle;
	} else if (!strncasecmp(peer, COM_CORE_REMOTE_SCHEME, COM_CORE_REMOTE_SCHEME_LEN)) {
		register int len;
		char *endptr;

		vtable->type = (int)SCHEME_REMOTE;
		peer += COM_CORE_REMOTE_SCHEME_LEN;

		for (len = 0; peer[len] && peer[len] != ':'; len++);
		if (peer[len] != ':') {
			ErrPrint("Invalid syntax: %s\n", peer);
			goto out;
		}

		addr = malloc(len + 1);
		if (!addr) {
			ErrPrint("Heap: %s\n", strerror(errno));
			goto out;
		}

		if (len > 0) {
			strncpy(addr, peer, len);
		}

		addr[len] = '\0';

		peer += len + 1;
		*port = strtoul(peer, &endptr, 10);
		if (*endptr != '\0' || peer == endptr) {
			ErrPrint("Invalid: %s[%d]\n", peer - len - 1, len + 1);
			free(addr);
			addr = NULL;
			goto out;
		}

		vtable->create_socket = create_inet_socket;
		vtable->setup_handle = setup_inet_handle;
	} else {
		/* Fallback to local scheme */
		vtable->type = (int)SCHEME_LOCAL;
		addr = strdup(peer);
		if (!addr) {
			ErrPrint("Heap: %s\n", strerror(errno));
			goto out;
		}

		vtable->create_socket = create_unix_socket;
		vtable->setup_handle = setup_unix_handle;
	}

out:
	return addr;
}

EAPI int secure_socket_create_client(const char *peer)
{
	int port;
	char *addr;
	int ret;
	struct function_table vtable;
	struct sockaddr *sockaddr;
	struct sockaddr_in in_addr;
	struct sockaddr_un un_addr;
	int handle;
	int addrlen;

	addr = parse_scheme(peer, &port, &vtable);
	if (!addr) {
		ErrPrint("peer: [%s] is not valid\n", peer);
		return -EINVAL;
	}

	switch (vtable.type) {
	case SCHEME_LOCAL:
	case SCHEME_SDLOCAL:
		sockaddr = (struct sockaddr *)&un_addr;
		addrlen = sizeof(un_addr);
		break;
	case SCHEME_REMOTE:
		sockaddr = (struct sockaddr *)&in_addr;
		addrlen = sizeof(in_addr);
		break;
	default:
		free(addr);
		return -EINVAL;
	}

	handle = vtable.create_socket(addr, port, sockaddr);
	free(addr);
	if (handle < 0) {
		return handle;
	}

	/**
	 * @note
	 * In case of a FD which is activated by systemd,
	 * Does not need to do connecting.
	 * It will be already connected.
	 */
	if (vtable.type != SCHEME_SDLOCAL) {
		ret = connect(handle, sockaddr, addrlen);
		if (ret < 0) {
			ret = -errno;
			ErrPrint("Failed to connect to server [%s] %s\n", peer, strerror(errno));
			if (close(handle) < 0) {
				ErrPrint("close: %s\n", strerror(errno));
			}

			return ret;
		}
	}

	ret = vtable.setup_handle(handle);
	if (ret < 0) {
		if (close(handle) < 0) {
			ErrPrint("close: %s\n", strerror(errno));
		}

		return ret;
	}

	return handle;
}

EAPI int secure_socket_create_server(const char *peer)
{
	return secure_socket_create_server_with_permission(peer, NULL);
}

EAPI int secure_socket_create_server_with_permission(const char *peer, const char *label)
{
	int port;
	char *addr;
	int handle;
	int ret;
	struct sockaddr *sockaddr;
	struct sockaddr_in in_addr;
	struct sockaddr_un un_addr;
	struct function_table vtable;
	int addrlen;

	addr = parse_scheme(peer, &port, &vtable);
	if (!addr) {
		ErrPrint("Failed to parse scheme\n");
		return -EINVAL;
	}

	switch (vtable.type) {
	case SCHEME_LOCAL:
	case SCHEME_SDLOCAL:
		sockaddr = (struct sockaddr *)&un_addr;
		addrlen = sizeof(un_addr);
		break;
	case SCHEME_REMOTE:
		sockaddr = (struct sockaddr *)&in_addr;
		addrlen = sizeof(in_addr);
		break;
	default:
		free(addr);
		return -EINVAL;
	}

	handle = vtable.create_socket(addr, port, sockaddr);
	free(addr);
	if (handle < 0) {
		return handle;
	}

	if (label) {
		/**
		 * @note
		 * Maybe this code will not work for FD from systemd.
		 * These functions should be done before "bind" and the systemd will do "bind" already. (maybe)
		 * Then these functions are not working on it.
		 * But I just leave it on here. ;)
		 *
		 * In case of the Tizen, they have security server which maintains all security related functionalities.
		 * So this API(fsetxattr) will not work in the Tizen.
		 * But if you are using this package for the other platform, like general linux system,
		 * It will work for you. But It just my expectation not tested.. ;)
		 */
		if (fsetxattr(handle, "security.SMACK64IPIN", label, strlen(label), 0) < 0) {
			ErrPrint("Failed to set SMACK label[%s] [%s]\n", label, strerror(errno));
		}

		if (fsetxattr(handle, "security.SMACK64IPOUT", label, strlen(label), 0) < 0) {
			ErrPrint("Failed to set SMACK label[%s] [%s]\n", label, strerror(errno));
		}
	}

	/**
	 * @note
	 * If the handle is created by systemd,
	 * We should not touch it anymore after gettting FD from sd library.
	 */
	if (vtable.type == SCHEME_SDLOCAL) {
		return handle;
	}

	ret = bind(handle, sockaddr, addrlen);
	if (ret < 0) {
		ret = -errno;
		ErrPrint("bind: %s\n", strerror(errno));
		if (close(handle) < 0) {
			ErrPrint("close: %s\n", strerror(errno));
		}
		return ret;
	}

	ret = listen(handle, BACKLOG);
	if (ret < 0) {
		ret = -errno;
		ErrPrint("listen: %s\n", strerror(errno));
		if (close(handle) < 0) {
			ErrPrint("close: %s\n", strerror(errno));
		}
		return ret;
	}

	if (vtable.type == SCHEME_LOCAL) {
		if (chmod(peer, 0666) < 0) {
			ErrPrint("Failed to change the permission of a socket (%s)\n", strerror(errno));
		}
	}

	return handle;
}

EAPI int secure_socket_get_connection_handle(int server_handle)
{
	struct sockaddr_in in_addr;
	struct sockaddr_un un_addr;
	struct sockaddr *addr;
	int handle;
	int ret;
	socklen_t size = sizeof(un_addr);

	/* Finding the largest buffer */
	if (sizeof(in_addr) > sizeof(un_addr)) {
		addr = (struct sockaddr *)&in_addr;
		size = sizeof(in_addr);
	} else {
		addr = (struct sockaddr *)&un_addr;
		size = sizeof(un_addr);
	}

	handle = accept(server_handle, addr, &size);
	if (handle < 0) {
		ret = -errno;
		ErrPrint("Failed to accept a new client %s\n", strerror(errno));
		return ret;
	}

	if (addr->sa_family == AF_UNIX) {
		ret = setup_unix_handle(handle);
		if (ret < 0) {
			if (close(handle) < 0) {
				ErrPrint("close: %s\n", strerror(errno));
			}

			handle = ret;
		}
	} else if (addr->sa_family == AF_INET) {
		ret = setup_inet_handle(handle);
		if (ret < 0) {
			if (close(handle) < 0) {
				ErrPrint("close: %s\n", strerror(errno));
			}

			handle = ret;
		}
	} else {
		ErrPrint("Unknown address family: %d\n", addr->sa_family);
	}

	return handle;
}

EAPI int secure_socket_send_with_fd(int handle, const char *buffer, int size, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr hdr;
		char control[CMSG_SPACE(sizeof(int))];
	} cmsgu;
	int ret;

	if (!buffer || size <= 0) {
		ErrPrint("Reject: 0 byte data sending\n");
		return -EINVAL;
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)buffer;
	iov.iov_len = size;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (fd >= 0) {
		struct cmsghdr *cmsg;
		int *cdata;

		msg.msg_control = cmsgu.control;
		msg.msg_controllen = sizeof(cmsgu.control);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cdata = (int *)CMSG_DATA(cmsg);
		*cdata = fd;
	}

	ret = sendmsg(handle, &msg, 0);
	if (ret < 0) {
		ret = -errno;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ErrPrint("handle[%d] size[%d] Try again [%s]\n", handle, size, strerror(errno));
			return -EAGAIN;
		}
		ErrPrint("Failed to send message [%s], handle(%d)\n", strerror(errno), handle);
		return ret;
	}

	return iov.iov_len;
}

EAPI int secure_socket_send(int handle, const char *buffer, int size)
{
	return secure_socket_send_with_fd(handle, buffer, size, -1);
}

EAPI int secure_socket_recv_with_fd(int handle, char *buffer, int size, int *sender_pid, int *fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char control[128];
	int _pid;
	int _fd;
	int ret;

	if (size <= 0 || !buffer) {
		return -EINVAL;
	}

	if (!sender_pid) {
		sender_pid = &_pid;
	}

	if (!fd) {
		fd = &_fd;
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buffer;
	iov.iov_len = size;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(handle, &msg, 0);
	if (ret < 0) {
		ret = -errno;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ErrPrint("handle[%d] size[%d] Try again [%s]\n", handle, size, strerror(errno));
			return -EAGAIN;
		}

		ErrPrint("Failed to recvmsg [%s]\n", strerror(errno));
		return ret;
	}

	if ((msg.msg_flags & MSG_CTRUNC) == MSG_CTRUNC) {
		ErrPrint("Controll buffer is too short (%d): %d, %d\n", msg.msg_controllen, size, sizeof(control));
	} else if (msg.msg_flags) {
		DbgPrint("Flags: %X\n", msg.msg_flags);
	}

	*sender_pid = -1;	/* In case of remote socket, cannot delivery this */ 
	*fd = -1;
	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
			struct ucred *cred;

			cred = (struct ucred *)CMSG_DATA(cmsg);
			*sender_pid = cred->pid;
		} else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			int *cdata;
			int count;

			count = cmsg->cmsg_len / CMSG_LEN(sizeof(int));
			cdata = (int *)CMSG_DATA(cmsg);
			if (count > 1 || &_fd == fd) {
				int i;

				ErrPrint("Unawared controll data. discards all\n");
				for (i = 0; i < count; i++) {
					if (close(cdata[i]) < 0) {
						ErrPrint("close: %d\n", errno);
					}
				}
			} else {
				*fd = *cdata;
			}
		} else {
			DbgPrint("Unknown message type\n");
		}

		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}

	if (ret == 0) {
		/*!< Disconnected */
		DbgPrint("Disconnected\n");
	}

	return ret == 0 ? 0 : iov.iov_len;
}

EAPI int secure_socket_recv(int handle, char *buffer, int size, int *sender_pid)
{
	return secure_socket_recv_with_fd(handle, buffer, size, sender_pid, NULL);
}

EAPI int secure_socket_destroy_handle(int handle)
{
	if (close(handle) < 0) {
		int ret;
		ret = -errno;
		ErrPrint("close: %s\n", strerror(errno));
		return ret;
	}

	return 0;
}

#undef _GNU_SOURCE

/* End of a file */
