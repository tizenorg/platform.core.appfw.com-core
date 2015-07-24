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

#ifndef _PACKET_H
#define _PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

struct packet;

enum packet_type {
	PACKET_REQ,
	PACKET_ACK,
	PACKET_REQ_NOACK,
	PACKET_ERROR
};

enum packet_flag {
	PACKET_FLAG_NOROUTE = 0x00, /*!< If possible, route this packet without care of the server */
	PACKET_FLAG_ROUTE = 0x01, /*!< This packet must has to be cared by the server */

	PACKET_FLAG_ERROR = 0xFF /*!< Invalid flag */
};

/*!
 * \brief Version of current protocol (packet)
 */
#define PACKET_VERSION	3

/*!
 * \brief Maximum length of a command string
 */
#define PACKET_MAX_CMD	24
#define PACKET_CMD_INT_TAG	0x01

/*!
 * \brief Create a packet
 * \details N/A
 * \remarks N/A
 * \param[in] command
 * \param[in] fmt
 * \param[in] ...
 * \return struct packet *
 * \retval
 * \sa packet_create_noack
 * \sa packet_create_reply
 * \sa packet_destroy
 * \sa packet_type
 */
extern struct packet *packet_create(const char *command, const char *fmt, ...);

/*!
 * \brief Create a packet which doesn't need reply
 * \details N/A
 * \remarks N/A
 * \param[in] command
 * \param[in] fmt
 * \param[in] ...
 * \return struct packet *
 * \retval
 * \sa packet_create
 * \sa packet_create_reply
 * \sa packet_destroy
 * \sa packet_type
 */
extern struct packet *packet_create_noack(const char *command, const char *fmt, ...);

/*!
 * \brief Create a reply packet
 * \details
 *   This API related with packet_create function
 *   If the packet is created using packet_create_noack, this function will returns ERROR
 * \remarks N/A
 * \param[in] packet
 * \param[in] fmt
 * \param[in] ...
 * \return struct packet *
 * \retval
 * \sa packet_create
 * \sa packet_create_reply
 * \sa packet_destroy
 */
extern struct packet *packet_create_reply(const struct packet *packet, const char *fmt, ...);

/*!
 * \brief Parse the data from a packet
 * \details
 *   parsed data will be destroyed if the packet is destroyed.
 * \remarks N/A
 * \param[in] packet
 * \param[in] fmt Format string: s - string, i - integer, d - double
 * \param[out] ... Lists of variables to get the address of each data.
 * \return int
 * \retval
 * \sa packet_create
 * \sa packet_create_reply
 * \sa pcaket_create_noack
 */
extern int packet_get(const struct packet *packet, const char *fmt, ...);

/*!
 * \brief Destroy a packet
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return int
 * \retval
 * \sa packet_create
 * \sa packet_create_reply
 * \sa packet_create_noack
 */
extern int packet_destroy(struct packet *packet);

/*!
 * \brief Increase the reference count
 * \details
 *   com_core_packet_send series functions will destroy the packet after it sends them
 *   If you want reuse the sent packet again, increase the reference count of a packet
 *   Then the packet will not be destroyed even though returns from the com_core_packet_send series functions
 * \remarks N/A
 * \param[in] packet
 * \return struct packet *
 * \retval
 * \sa packet_unref
 */
extern struct packet *packet_ref(struct packet *packet);

/*!
 * \brief Decrease the reference count
 * \details
 *   If the reference count reaches to ZERO, the packet will be destroyed automatically.
 * \remarks N/A
 * \param[in] packet
 * \return struct packet *
 * \retval
 * \sa packet_ref
 */
extern struct packet *packet_unref(struct packet *packet);


/*!
 * \brief Get the payload.
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return void *
 * \retval
 */
extern const void * const packet_data(const struct packet *packet);

/*!
 * \brief Get the sequence number
 * \details
 *   Sequence number is based on current clock time.
 *   Its uniq attribute will be kept if your system supports clock_get_time.
 * \remarks N/A
 * \param[in] packet
 * \return double
 * \retval 0 Invalid argument
 * \retval sequence number
 */
extern const double const packet_seq(const struct packet *packet);

/*!
 * \brief Get the type of packet
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return enum packet_type
 * \retval PACKET_REQ Request packet
 * \retval PACKET_ACK Reply packet
 * \retval PACKET_REQ_NOACK Request packet but it doesn't requires reply packet
 * \retval PACKET_ERROR Error, invalid argument.
 * \sa packet_create
 * \sa packet_create_noack
 * \sa packet_create_reply
 */
extern const enum packet_type const packet_type(const struct packet *packet);


/*!
 * \brief Get the packet flag
 * \details
 *   Packet router process should concerns flag.
 *   If the packet flag'd _ROUTE, the server must has to route it by its address.
 *   So the router process should have routing table.
 *   And the router process should manage all address which are assigned to each procecss.
 * \remarks
 *   Address and PID are different.
 * \param[in] packet
 * \return enum packet_flag
 * \retval PACKET_FLAG_NOROUTE Default packet.
 * \retval PACKET_FLAG_ROUTE Server process must has to route this packet before reach to its client.
 * \sa packet_set_flag
 */
extern const enum packet_flag const packet_flag(const struct packet *packet);

/*!
 * \brief Set the packet flag
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \param[in] flag
 * \return int
 * \retval -EINVAL Invalid argument
 * \retval 0 Successfully set new flag
 * \sa packet_flag
 */
extern int packet_set_flag(struct packet *packet, enum packet_flag flag);

/*!
 * \brief Get the source address of a packet
 * \details N/A
 * \remarks
 *   Address must has not to be ZERO it will be delat as an error case.
 * \param[in] packet
 * \return unsigned long
 * \retval 0 Invalid argument
 * \retval Address
 * \sa packet_set_source
 */
extern const unsigned long const packet_source(const struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks
 *   Address must has not to be ZERO it will be delat as an error case.
 * \param[in] packet
 * \param[in] source
 * \return int
 * \retval
 * \sa packet_source
 */
extern int packet_set_source(struct packet *packet, unsigned long source);

/*!
 * \brief
 * \details N/A
 * \remarks
 *   Address must has not to be ZERO it will be delat as an error case.
 * \param[in] packet
 * \return unsigned long
 * \retval
 * \sa packet_set_destination
 */
extern const unsigned long const packet_destination(const struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks
 *   Address must has not to be ZERO it will be delat as an error case.
 * \param[in] packet
 * \param[in] destination
 * \return int
 * \retval
 * \sa packet_destination
 */
extern int packet_set_destination(struct packet *packet, unsigned long destination);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \param[in] mask
 * \return int
 * \retval
 * \sa packet_mask
 */
extern int packet_set_mask(struct packet *packet, unsigned long mask);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return unsigned long
 * \retval
 * \sa packet_set_mask
 */
extern unsigned long packet_mask(const struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return int
 * \retval
 * \sa packet_set_source
 * \sa packet_set_destination
 */
extern int packet_swap_address(struct packet *packet);


/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return int
 * \retval
 * \sa PACKET_VERSION
 */
extern const int const packet_version(const struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return int
 * \retval
 */
extern const int const packet_payload_size(const struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return char *
 * \retval
 * \sa packet_create
 * \sa packet_create_noack
 */
extern const char * const packet_command(const const struct packet *packet);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \return int
 * \retval
 */
extern const int const packet_header_size(void);

/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \return int
 * \retval
 */
extern const int const packet_size(const struct packet *packet);


/*!
 * \brief
 * \details N/A
 * \remarks N/A
 * \param[in] packet
 * \param[in] offset
 * \param[in] data
 * \param[in] size
 * \return struct packet *
 * \retval
 */
extern struct packet *packet_build(struct packet *packet, int offset, void *data, int size);

extern int packet_fd(const struct packet *packet);
extern int packet_set_fd(struct packet *packet, int fd);
extern int packet_set_fd_close_handler_on_destroy(struct packet *packet, void (*close_cb)(int fd, void *data), void *data);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
