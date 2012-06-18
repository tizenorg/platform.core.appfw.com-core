#ifdef __cplusplus
extern "C" {
#endif

enum connector_event_type {
	CONNECTOR_CONNECTED,
	CONNECTOR_DISCONNECTED,
};

extern int connector_server_create(const char *addr, int is_sync, int (*service_cb)(int fd, int readsize, void *data), void *data);
extern int connector_client_create(const char *addr, int is_sync, int (*service_cb)(int fd, int readsize, void *data), void *data);
extern int connector_server_destroy(int handle);
extern int connector_client_destroy(int handle);

extern int connector_add_event_callback(enum connector_event_type type, int (*service_cb)(int handle, void *data), void *data);
extern void *connector_del_event_callback(enum connector_event_type type, int (*service_cb)(int handle, void *data), void *data);

#ifdef __cplusplus
}
#endif

/* End of a file */
