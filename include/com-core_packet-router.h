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

#ifndef _COM_CORE_PACKET_ROUTER_H
#define _COM_CORE_PACKET_ROUTER_H

#ifdef __cplusplus
extern "C" {
#endif

enum com_core_route_event_type {
	COM_CORE_ROUTE_CONNECTED,
	COM_CORE_ROUTE_DISCONNECTED,
	COM_CORE_ROUTE_ERROR,
};

extern int com_core_packet_router_add_route(int handle, unsigned long address, int to);
extern int com_core_packet_router_del_route(int handle, unsigned long address);
extern int com_core_packet_router_update_route(int handle, unsigned long address, int to);

extern int com_core_packet_router_add_event_callback(enum com_core_route_event_type type, int (*evt_cb)(int handle, void *data), void *data);
extern int com_core_packet_router_del_event_callback(enum com_core_route_event_type type, int (*evt_cb)(int handle, void *data), void *data);

extern int com_core_packet_router_server_init(const char *sock, double timeout, struct method *table);
extern void *com_core_packet_router_server_fini(int handle);

extern int com_core_packet_router_client_init(const char *sock, double timeout, struct method *table);
extern void *com_core_packet_router_client_fini(int handle);

extern int com_core_packet_router_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data);
extern int com_core_packet_router_send_only(int handle, struct packet *packet);
extern struct packet *com_core_packet_router_oneshot_send(const char *addr, struct packet *packet, double timeout);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
