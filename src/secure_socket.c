#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>

#include <dlog.h>

#include "secure_socket.h"
#include "debug.h"
#include "util.h"

#define BACKLOG 50	/*!< Accept only 50 connections as default */

int errno;

static inline int create_socket(const char *peer, struct sockaddr_un *addr)
{
	int len;
	int handle;

	len = sizeof(*addr);
	bzero(addr, len);

	if (strlen(peer) >= sizeof(addr->sun_path)) {
		ErrPrint("peer %s is too long to remember it\\n", peer);
		return -1;
	}

	/* We can believe this has no prob, because
	 * we already check the size of add.rsun_path
	 */
	strcpy(addr->sun_path, peer);
	addr->sun_family = AF_UNIX;

	handle = socket(PF_UNIX, SOCK_STREAM, 0);
	if (handle < 0) {
		ErrPrint("Failed to create a socket %s\n", strerror(errno));
		return -1;
	}

	return handle;
}

EAPI int secure_socket_create_client(const char *peer)
{
	struct sockaddr_un addr;
	int handle;
	int state;
	int on = 1;

	handle = create_socket(peer, &addr);
	if (handle < 0)
		return handle;

	state = connect(handle, (struct sockaddr *)&addr, sizeof(addr));
	if (state < 0) {
		ErrPrint("Failed to connect to server [%s] %s\n",
							peer, strerror(errno));
		if (close(handle) < 0)
			ErrPrint("close a handle: %s\n", strerror(errno));

		return -1;
	}

	if (setsockopt(handle, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
		ErrPrint("Failed to change sock opt : %s\n", strerror(errno));
		if (close(handle) < 0)
			ErrPrint("close a handle: %s\n", strerror(errno));
		return -1;
	}

	return handle;
}

EAPI int secure_socket_create_server(const char *peer)
{
	int handle;
	int state;
	struct sockaddr_un addr;

	handle = create_socket(peer, &addr);
	if (handle < 0)
		return handle;

	state = bind(handle, &addr, sizeof(addr));
	if (state < 0) {
		ErrPrint("Failed to bind a socket %s\n", strerror(errno));
		if (close(handle) < 0)
			ErrPrint("Close a handle : %s\n", strerror(errno));

		return -1;
	}

	state = listen(handle, BACKLOG);
	if (state < 0) {
		ErrPrint("Failed to listen a socket %s\n", strerror(errno));

		if (close(handle) < 0)
			ErrPrint("Close a handle : %s\n", strerror(errno));

		return -1;
	}

	if (chmod(peer, 0666) < 0)
		ErrPrint("Failed to change the permission of a socket (%s)\n",
							strerror(errno));

	return handle;
}

EAPI int secure_socket_get_connection_handle(int server_handle)
{
	struct sockaddr_un addr;
	int handle;
	int on = 1;
	socklen_t size = sizeof(addr);

	handle = accept(server_handle, (struct sockaddr *)&addr, &size);
	if (handle < 0) {
		ErrPrint("Failed to accept a new client %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(handle, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
		ErrPrint("Failed to change sock opt : %s\n", strerror(errno));
		if (close(handle) < 0)
			ErrPrint("Close a handle: %s\n", strerror(errno));
		return -1;
	}

	return handle;
}

EAPI int secure_socket_send(int handle, const char *buffer, int size)
{
	struct msghdr msg;
	struct iovec iov;
	int ret;

	if (!buffer || size <= 0) {
		ErrPrint("Reject: 0 byte data sending\n");
		return -EINVAL;
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)buffer;
	iov.iov_len = size;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(handle, &msg, 0);
	if (ret < 0) {
		ret = -errno;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ErrPrint("handle[%d] size[%d] Try again [%s]\n", handle, size, strerror(errno));
			return -EAGAIN;
		}
		ErrPrint("Failed to send message [%s]\n", strerror(errno));
		return ret;
	}

	return iov.iov_len;
}

EAPI int secure_socket_recv(int handle, char *buffer, int size, int *sender_pid)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char control[1024];
	int ret;

	if (!sender_pid || size <= 0 || !buffer)
		return -EINVAL;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buffer;
	iov.iov_len = size;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(handle, &msg, 0);
	if (ret == 0) {
		/*!< Disconnected */
		DbgPrint("Disconnected\n");
		return 0;
	}

	if (ret < 0) {
		ret = -errno;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ErrPrint("handle[%d] size[%d] Try again [%s]\n", handle, size, strerror(errno));
			return -EAGAIN;
		}

		ErrPrint("Failed to recvmsg [%s]\n", strerror(errno));
		return ret;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg) {
		if (cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SCM_CREDENTIALS)	{
			struct ucred *cred;
			cred = (struct ucred *)CMSG_DATA(cmsg);
			*sender_pid = cred->pid;
		}

		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}

	return iov.iov_len;
}

EAPI int secure_socket_destroy_handle(int handle)
{
	DbgPrint("Close socket handle %d\n", handle);
	if (close(handle) < 0) {
		ErrPrint("Failed to close a handle: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

#undef _GNU_SOURCE
/* End of a file */
