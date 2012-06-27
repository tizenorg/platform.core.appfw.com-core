#ifdef __cplusplus
extern "C" {
#endif

enum com_core_event_type {
	CONNECTOR_CONNECTED,
	CONNECTOR_DISCONNECTED,
};

extern int com_core_server_create(const char *addr, int is_sync, int (*service_cb)(int fd, int readsize, void *data), void *data);
extern int com_core_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, int readsize, void *data), void *data);
extern int com_core_server_destroy(int handle);
extern int com_core_client_destroy(int handle);

extern int com_core_add_event_callback(enum com_core_event_type type, int (*service_cb)(int handle, void *data), void *data);
extern void *com_core_del_event_callback(enum com_core_event_type type, int (*service_cb)(int handle, void *data), void *data);

#ifdef __cplusplus
}
#endif

/* End of a file */
