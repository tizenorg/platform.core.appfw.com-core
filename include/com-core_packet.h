#ifdef __cplusplus
extern "C" {
#endif

struct method {
	const char *cmd;
	struct packet *(*handler)(pid_t pid, int handle, struct packet *packet);
};

extern int com_core_packet_async_send(int handle, struct packet *packet, int (*recv_cb)(pid_t, int handle, const struct packet *packet, void *data), void *data);
extern int com_core_packet_send_only(int handle, struct packet *packet);
extern struct packet *com_core_packet_oneshot_send(const char *addr, struct packet *packet);

extern int com_core_packet_client_init(const char *addr, int is_sync, struct method *table);
extern int com_core_packet_client_fini(int handle);
extern int com_core_packet_server_init(const char *addr, struct method *table);
extern int com_core_packet_server_fini(int handle);

#ifdef __cplusplus
}
#endif

/* End of a file */
