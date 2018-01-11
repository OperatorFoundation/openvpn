#ifndef OPENVPN_PLUGIN_OBFS_TEST_H
#define OPENVPN_PLUGIN_OBFS_TEST_H 1

#include "openvpn-vsocket.h"

extern struct openvpn_vsocket_vtab obfs_test_socket_vtab;
void obfs_test_initialize_socket_vtab(void);
void obfs_test_munge_addr(struct sockaddr *addr, openvpn_vsocket_socklen_t len);
size_t obfs_test_max_munged_buf_size(size_t clear_size);
size_t obfs_test_munge_buf(char *out, const char *in, size_t len);
ssize_t obfs_test_unmunge_buf(char *buf, size_t len);

#endif /* !OPENVPN_PLUGIN_OBFS_TEST_H */
