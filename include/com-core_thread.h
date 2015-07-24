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

#ifndef _COM_CORE_THREAD_H
#define _COM_CORE_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

extern int com_core_thread_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, void *data), void *data);
extern int com_core_thread_server_create(const char *addr, int is_sync, const char *label, int (*service_cb)(int fd, void *data), void *data);
extern int com_core_thread_client_create_by_fd(int client_fd, int is_sync, int (*service_cb)(int fd, void *data), void *data);

extern int com_core_thread_server_destroy(int handle);
extern int com_core_thread_client_destroy(int handle);

extern int com_core_thread_recv(int handle, char *buffer, int size, int *sender_pid, double timeout);
extern int com_core_thread_send(int handle, const char *buffer, int size, double timeout);

extern int com_core_thread_recv_with_fd(int handle, char *buffer, int size, int *sender_pid, double timeout, int *fd);
extern int com_core_thread_send_with_fd(int handle, const char *buffer, int size, double timeout, int fd);

#ifdef __cplusplus
}
#endif

#endif
/* End of a file */
