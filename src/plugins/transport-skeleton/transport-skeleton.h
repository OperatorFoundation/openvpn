#ifndef OPENVPN_PLUGIN_transport_skeleton_H
#define OPENVPN_PLUGIN_transport_skeleton_H 1

#include "openvpn-plugin.h"
#include "openvpn-vsocket.h"

#define transport_skeleton_PLUGIN_NAME "transport-skeleton"

struct transport_skeleton_context;
extern struct openvpn_vsocket_vtab transport_skeleton_socket_vtab;
void transport_skeleton_initialize_socket_vtab(void);
//void transport_skeleton_munge_addr(struct sockaddr *addr, openvpn_vsocket_socklen_t len);
//size_t transport_skeleton_max_munged_buf_size(size_t clear_size);
//size_t transport_skeleton_munge_buf(char *out, const char *in, size_t len);
//ssize_t transport_skeleton_unmunge_buf(char *buf, size_t len);
void transport_skeleton_log(struct transport_skeleton_context *ctx,
                   openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_transport_skeleton_H */
