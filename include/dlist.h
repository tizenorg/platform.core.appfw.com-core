#define dlist_remove_data(list, data) do { \
	struct dlist *l; \
	l = dlist_find_data(list, data); \
	list = dlist_remove(list, l); \
} while (0)

#define dlist_foreach(list, l, data) \
	for ((l) = (list); (l) && ((data) = dlist_data(l)); (l) = dlist_next(l))

#define dlist_foreach_safe(list, l, n, data) \
	for ((l) = (list), (n) = dlist_next(l); \
		(l) && ((data) = dlist_data(l)); \
		(l) = (n), (n) = dlist_next(l))

struct dlist;

extern struct dlist *dlist_append(struct dlist *list, void *data);
extern struct dlist *dlist_prepend(struct dlist *list, void *data);
extern struct dlist *dlist_remove(struct dlist *list, struct dlist *l);
extern struct dlist *dlist_find_data(struct dlist *list, void *data);
extern void *dlist_data(struct dlist *l);
extern struct dlist *dlist_next(struct dlist *l);
extern struct dlist *dlist_prev(struct dlist *l);
extern int dlist_count(struct dlist *l);
extern struct dlist *dlist_nth(struct dlist *l, int nth);

/* End of a file */
