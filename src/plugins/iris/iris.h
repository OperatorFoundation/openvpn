#ifndef OPENVPN_PLUGIN_iris_H
#define OPENVPN_PLUGIN_iris_H 1

#include "openvpn-plugin.h"
#include "openvpn-vsocket.h"

#define iris_PLUGIN_NAME "iris"

struct iris_context
{
    struct openvpn_plugin_callbacks *global_vtab;
    char *password;
};

extern struct openvpn_vsocket_vtab iris_socket_vtab;

void iris_initialize_socket_vtab(void);
void iris_log(struct iris_context *ctx,
                   openvpn_plugin_log_flags_t flags, const char *fmt, ...);


#endif /* !OPENVPN_PLUGIN_iris_H */
