#ifndef OPENVPN_PLUGIN_iris_H
#define OPENVPN_PLUGIN_iris_H 1

#include "openvpn-plugin.h"
#include "openvpn-vsocket.h"

#define iris_PLUGIN_NAME "iris"

struct iris_context;
extern struct openvpn_vsocket_vtab iris_socket_vtab;
void iris_initialize_socket_vtab(void);
//void iris_munge_addr(struct sockaddr *addr, openvpn_vsocket_socklen_t len);
//size_t iris_max_munged_buf_size(size_t clear_size);
//size_t iris_munge_buf(char *out, const char *in, size_t len);
//ssize_t iris_unmunge_buf(char *buf, size_t len);
void iris_log(struct iris_context *ctx,
                   openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_iris_H */
