/*
 * Copyright 2012  Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

extern int com_core_packet_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data);
extern int com_core_packet_send_only(int handle, struct packet *packet);
extern struct packet *com_core_packet_oneshot_send(const char *addr, struct packet *packet, double timeout);
extern int com_core_packet_client_init(const char *addr, int is_sync, struct method *table);
extern int com_core_packet_client_fini(int handle);
extern int com_core_packet_server_init(const char *addr, struct method *table);
extern int com_core_packet_server_fini(int handle);
extern void com_core_packet_use_thread(int flag);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
