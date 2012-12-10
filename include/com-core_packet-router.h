/*!
 * \NOTE
 * This component uses THREAD.
 * If you want to keep your application running without multiple threads,
 * DO NOT USE THIS.
 */

enum com_core_route_event_type {
	COM_CORE_ROUTE_CONNECTED,
	COM_CORE_ROUTE_DISCONNECTED,
	COM_CORE_ROUTE_ERROR,
};

extern int com_core_packet_router_add_link(int handle, int from, int to);
extern int com_core_packet_router_del_link_by_from(int handle, int from);
extern int com_core_packet_router_del_link_by_to(int handle, int to);

extern int com_core_packet_router_add_event_callback(enum com_core_route_event_type type, int (*evt_cb)(int handle, void *data), void *data);
extern int com_core_packet_router_del_event_callback(enum com_core_route_event_type type, int (*evt_cb)(int handle, void *data), void *data);

extern int com_core_packet_router_server_create(const char *sock, double timeout, struct packet *(*service)(int handle, pid_t pid, const struct packet *packet, void *data), void *data);
extern int com_core_packet_router_client_create(const char *sock, double timeout, struct packet *(*service)(int handle, pid_t pid, const struct packet *packet, void *data), void *data);
extern void *com_core_packet_router_destroy(int handle);

extern int com_core_packet_router_async_send(int handle, struct packet *packet, double timeout, int (*recv_cb)(pid_t pid, int handle, const struct packet *packet, void *data), void *data);
extern int com_core_packet_router_send_only(int handle, struct packet *packet);
extern struct packet *com_core_packet_router_oneshot_send(const char *addr, struct packet *packet, double timeout);

/* End of a file */
