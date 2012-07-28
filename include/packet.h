#ifdef __cplusplus
extern "C" {
#endif

struct packet;

enum packet_type {
	PACKET_REQ,
	PACKET_ACK,
	PACKET_REQ_NOACK,
	PACKET_ERROR,
};

#define PACKET_VERSION	1
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
extern const int const packet_version(const struct packet *packet);
extern const int const packet_payload_size(const struct packet *packet);
extern const char * const packet_command(const const struct packet *packet);
extern const int const packet_header_size(void);
extern const int const packet_size(const struct packet *packet);

extern struct packet *packet_build(struct packet *packet, int offset, void *data, int size);

#ifdef __cplusplus
}
#endif

/* End of a file */
