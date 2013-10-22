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

#define PACKET_VERSION	2
#define PACKET_MAX_CMD	24

extern struct packet *packet_create(const char *command, const char *fmt, ...);
extern struct packet *packet_create_noack(const char *command, const char *fmt, ...);
extern struct packet *packet_create_reply(const struct packet *packet, const char *fmt, ...);
extern int packet_get(const struct packet *packet, const char *fmt, ...);
extern int packet_destroy(struct packet *packet);
extern struct packet *packet_ref(struct packet *packet);
extern struct packet *packet_unref(struct packet *packet);

extern const void * const packet_data(const struct packet *packet);
extern const double const packet_seq(const struct packet *packet);
extern const enum packet_type const packet_type(const struct packet *packet);

extern const enum packet_flag const packet_flag(const struct packet *packet);
extern int packet_set_flag(struct packet *packet, enum packet_flag flag);
extern const unsigned long const packet_source(const struct packet *packet);
extern int packet_set_source(struct packet *packet, unsigned long source);
extern const unsigned long const packet_destination(const struct packet *packet);
extern int packet_set_destination(struct packet *packet, unsigned long destination);
extern int packet_set_mask(struct packet *packet, unsigned long mask);
extern unsigned long packet_mask(const struct packet *packet);
extern int packet_swap_address(struct packet *packet);

extern const int const packet_version(const struct packet *packet);
extern const int const packet_payload_size(const struct packet *packet);
extern const char * const packet_command(const const struct packet *packet);
extern const int const packet_header_size(void);
extern const int const packet_size(const struct packet *packet);

extern struct packet *packet_build(struct packet *packet, int offset, void *data, int size);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
