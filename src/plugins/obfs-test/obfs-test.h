#ifndef OPENVPN_PLUGIN_OBFS_TEST_H
#define OPENVPN_PLUGIN_OBFS_TEST_H 1

#include "openvpn-plugin.h"
#include "openvpn-transport.h"

#define OBFS_TEST_PLUGIN_NAME "obfs-test"

struct obfs_test_context;

struct obfs_test_args
{
    const char *error;
    int offset;
};

extern struct openvpn_transport_bind_vtab1 obfs_test_bind_vtab;
extern struct openvpn_transport_socket_vtab1 obfs_test_socket_vtab;

void obfs_test_initialize_vtabs_platform(void);

void obfs_test_munge_addr(struct sockaddr *addr, openvpn_transport_socklen_t len);

size_t obfs_test_max_munged_buf_size(size_t clear_size);

size_t obfs_test_munge_buf(struct obfs_test_args *how,
                           char *out, const char *in, size_t len);

ssize_t obfs_test_unmunge_buf(struct obfs_test_args *how,
                              char *buf, size_t len);

openvpn_transport_args_t obfs_test_parseargs(void *plugin_handle,
                                             const char *const *argv, int argc);

const char *obfs_test_argerror(openvpn_transport_args_t args);

void obfs_test_freeargs(openvpn_transport_args_t args);

void obfs_test_log(struct obfs_test_context *ctx,
                   openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_OBFS_TEST_H */
