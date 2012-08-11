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

#ifndef _COM_CORE_H
#define _COM_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

enum com_core_event_type {
	CONNECTOR_CONNECTED,
	CONNECTOR_DISCONNECTED,
};

extern int com_core_server_create(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data);
extern int com_core_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data);
extern int com_core_server_destroy(int handle);
extern int com_core_client_destroy(int handle);

extern int com_core_add_event_callback(enum com_core_event_type type, int (*service_cb)(int handle, void *data), void *data);
extern void *com_core_del_event_callback(enum com_core_event_type type, int (*service_cb)(int handle, void *data), void *data);

/*!
 * \brief If the connection is lost, this recv function will call the disconnected callback.
 */
extern int com_core_recv(int handle, char *buffer, int size, int *sender_pid, double timeout);
extern int com_core_send(int handle, const char *buffer, int size, double timeout);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
