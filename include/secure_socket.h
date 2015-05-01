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
 * remote://IPADDR:PORT
 * remote://:PORT	=> Using INADDR_ANY in this case
 */
#define COM_CORE_REMOTE_SCHEME		"remote://"
#define COM_CORE_REMOTE_SCHEME_LEN	(9)

/*
 * sdlocal:///tmp/.socket.file => /tmp/.socket.file
 */
#define COM_CORE_SD_LOCAL_SCHEME	"sdlocal://"
#define COM_CORE_SD_LOCAL_SCHEME_LEN	(10)

/*!
 * \brief Create client connection
 * \details N/A
 * \remarks N/A
 * \param[in] peer
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_create_client(const char *peer);

/*!
 * \brief Create server connection
 * \details N/A
 * \remarks N/A
 * \param[in] peer
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_create_server(const char *peer);

/*!
 * \brief Create server connection
 * \details N/A
 * \remarks N/A
 * \param[in] peer
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_create_server_with_permission(const char *peer, const char *label);


/*!
 * \brief Get the raw handle to use it for non-blocking mode.
 * \details N/A
 * \remarks N/A
 * \param[in] server_handle
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_get_connection_handle(int server_handle);

/*!
 * \brief Send data to the connected peer.
 * \details N/A
 * \remarks N/A
 * \param[in] conn
 * \param[in] buffer
 * \param[in] size
 * \param[in] fd Shared fd which will be used from receiver process.
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_send(int conn, const char *buffer, int size);
extern int secure_socket_send_with_fd(int handle, const char *buffer, int size, int fd);

/*!
 * \brief Recv data from the connected peer. and its PID value
 * \details N/A
 * \remarks N/A
 * \param[in] connn
 * \param[out] buffer
 * \param[in] size
 * \param[out] sender_pid
 * \param[out] fd  shared fd which is comes from sender process.
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_recv(int conn, char *buffer, int size, int *sender_pid);
extern int secure_socket_recv_with_fd(int conn, char *buffer, int size, int *sender_pid, int *fd);

/*!
 * \brief Destroy a connection
 * \details N/A
 * \remarks N/A
 * \param[in] conn
 * \return int
 * \retval
 * \sa
 */
extern int secure_socket_destroy_handle(int conn);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
