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

#ifndef _SECURE_SOCKET_H
#define _SECURE_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * local:///tmp/.socket.file => /tmp/.socket.file
 */
#define COM_CORE_LOCAL_SCHEME		"local://"
#define COM_CORE_LOCAL_SCHEME_LEN	(8)

/*!
 * sdlocal:///tmp/.socket.file => /tmp/.socket.file
 */
#define COM_CORE_SD_LOCAL_SCHEME	"sdlocal://"
#define COM_CORE_SD_LOCAL_SCHEME_LEN	(10)

/*!
 * remote://IPADDR:PORT
 * remote://:PORT	=> Using INADDR_ANY in this case
 */
#define COM_CORE_REMOTE_SCHEME		"remote://"
#define COM_CORE_REMOTE_SCHEME_LEN	(9)

/*
 * Create client connection
 */
extern int secure_socket_create_client(const char *peer);

/*
 * Create server connection
 */
extern int secure_socket_create_server(const char *peer);

/*
 * Get the raw handle to use it for non-blocking mode.
 */
extern int secure_socket_get_connection_handle(int server_handle);

/*
 * Send data to the connected peer.
 */
extern int secure_socket_send(int conn, const char *buffer, int size);

/*
 * Recv data from the connected peer. and its PID value
 */
extern int secure_socket_recv(int conn, char *buffer, int size, int *sender_pid);

/*
 * Destroy a connection
 */
extern int secure_socket_destroy_handle(int conn);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */