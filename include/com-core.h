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

#ifndef _COM_CORE_H
#define _COM_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

enum com_core_event_type {
	CONNECTOR_CONNECTED,
	CONNECTOR_DISCONNECTED
};

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] addr
 * \param[in] is_sync
 * \param[in] service_cb
 * \param[in] data
 * \return int
 * \retval
 * \sa
 */
extern int com_core_server_create(const char *addr, int is_sync, const char *label, int (*service_cb)(int fd, void *data), void *data);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] addr
 * \param[in] is_sync
 * \param[in] service_cb
 * \param[in] data
 * \return int
 * \retval
 * \sa
 */
extern int com_core_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data);

/*!
 */
extern int com_core_client_create_by_fd(int client_fd, int is_sync, int (*service_cb)(int fd, void *data), void *data);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \return int
 * \retval
 * \sa
 */
extern int com_core_server_destroy(int handle);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \return int
 * \retval
 * \sa
 */
extern int com_core_client_destroy(int handle);

/*!
 * \brief Used to handling the changing event of connection status.
 *        These two functions can be work with com_core_thread series functions.
 * \details N/A
 * \remarks N/A
 * \param[in] type
 * \param[in] service_cb
 * \param[in] data
 * \return int
 * \retval
 * \sa
 */
extern int com_core_add_event_callback(enum com_core_event_type type, int (*service_cb)(int handle, void *data), void *data);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] type
 * \param[in] service_cb
 * \param[in] data
 * \return void *
 * \retval
 * \sa
 */
extern void *com_core_del_event_callback(enum com_core_event_type type, int (*service_cb)(int handle, void *data), void *data);

/*!
 * \brief If the connection is lost, this recv function will call the disconnected callback.
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \param[in] buffer
 * \param[in] size
 * \param[in] sender_pid
 * \param[in] timeout
 * \return int
 * \retval
 * \sa
 */
extern int com_core_recv(int handle, char *buffer, int size, int *sender_pid, double timeout);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \param[in] buffer
 * \param[in] size
 * \param[in] timeout
 * \return int
 * \retval
 * \sa
 */
extern int com_core_send(int handle, const char *buffer, int size, double timeout);

/**
 * @brief
 * @details
 * @remarks
 * @param[in] handle
 * @param[in] buffer
 * @param[in] size
 * @param[in] timeout
 * @param[in] fd
 * @return int
 * @retval
 * @sa
 */
extern int com_core_send_with_fd(int handle, const char *buffer, int size, double timeout, int fd);

/**
 * @brief
 * @details
 * @remarks
 * @param[in] handle
 * @param[out] buffer
 * @param[in] size
 * @param[out] sender_pid
 * @param[in] timeout
 * @param[out] fd
 */
extern int com_core_recv_with_fd(int handle, char *buffer, int size, int *sender_pid, double timeout, int *fd);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
