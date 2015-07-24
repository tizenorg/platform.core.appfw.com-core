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

#ifndef _COM_CORE_PACKET_H
#define _COM_CORE_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

struct method {
	const char *cmd;
	struct packet *(*handler)(pid_t pid, int handle, const struct packet *packet);
};

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \param[in] packet
 * \param[in] timeout
 * \param[in] recv_cb
 * \param[in] data
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \param[in] packet
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_send_only(int handle, struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] addr
 * \param[in] packet
 * \param[in] timeout
 * \return struct packet *
 * \retval
 * \sa
 */
extern struct packet *com_core_packet_oneshot_send(const char *addr, struct packet *packet, double timeout);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] addr
 * \param[in] is_sync
 * \param[in] table
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_client_init(const char *addr, int is_sync, struct method *table);

/**
 * @brief
 * @details
 * @remarks
 * @param[in]
 * @return int
 * @retval
 * @sa
 */
extern int com_core_packet_client_init_by_fd(int fd, int is_sync, struct method *table);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_client_fini(int handle);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] addr
 * \param[in] table
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_server_init(const char *addr, struct method *table);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] addr
 * \param[in] table
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_server_init_with_permission(const char *addr, struct method *table, const char *label);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] handle
 * \return int
 * \retval
 * \sa
 */
extern int com_core_packet_server_fini(int handle);
extern void com_core_packet_server_disconnect_handle(int handle);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] flag
 * \return void
 * \sa
 */
extern void com_core_packet_use_thread(int flag);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
