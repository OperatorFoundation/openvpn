#ifndef OPENVPN_PLUGIN_shapeshifter_H
#define OPENVPN_PLUGIN_shapeshifter_H 1

#include "openvpn-plugin.h"
#include "openvpn-vsocket.h"

#define shapeshifter_PLUGIN_NAME "shapeshifter"

struct shapeshifter_context;
extern struct openvpn_vsocket_vtab shapeshifter_socket_vtab;
void shapeshifter_initialize_socket_vtab(void);
//void shapeshifter_munge_addr(struct sockaddr *addr, openvpn_vsocket_socklen_t len);
//size_t shapeshifter_max_munged_buf_size(size_t clear_size);
//size_t shapeshifter_munge_buf(char *out, const char *in, size_t len);
//ssize_t shapeshifter_unmunge_buf(char *buf, size_t len);
void shapeshifter_log(struct shapeshifter_context *ctx,
                   openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_shapeshifter_H */
