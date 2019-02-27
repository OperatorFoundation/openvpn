/*
 *  Transport API handling code
 *
 *  Copyright (C) 2018 Robin Tarsiger <rtt@dasyatidae.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef OPENVPN_TRANSPORT_H
#define OPENVPN_TRANSPORT_H

#ifdef ENABLE_PLUGIN

#include "plugin.h"
#include "openvpn-transport.h"

/* INDIRECT does not have any overhead per se, but it depends on what is
 * implemented by the transport plugin
 */
#define INDIRECT_HEADER_SIZE    0

/* Given a list of plugins and an argument list for a desired
 * transport plugin instance, prepare to bind new link sockets using
 * that transport plugin and args. If all succeeds, return true, and:
 *
 *   *vtabp is set to the vtable by which to bind new link sockets.
 *   *handlep is set to the plugin handle to use in bind calls.
 *   *argsp is set to the args value to use in bind calls. It is
 *     the caller's responsibility to call freeargs on it later.
 *
 * Otherwise, return false, and the values of all of the above are
 * undefined. None of the output pointers may be NULL.
 */
bool transport_prepare(const struct plugin_list *plugins,
                       const char **transport_plugin_argv,
                       struct openvpn_transport_bind_vtab1 **vtabp,
                       openvpn_plugin_handle_t *handlep,
                       openvpn_transport_args_t *argsp);

/* Bind a virtual socket given an address family and list of potential
 * bind addresses. bind_addresses may be NULL, in which case an
 * unspecified address of the correct family is used. The virtual
 * socket comes from a transport plugin in the list of plugins which
 * matches transport_plugin_argv, which is used for any
 * connection-specific parameters the plugin may require.
 *
 * Raises a fatal error if the socket cannot be bound.
 */
openvpn_transport_socket_t
transport_bind(const struct plugin_list *plugins,
               const char **transport_plugin_argv, sa_family_t ai_family,
               struct addrinfo *bind_addresses);

/* Mutates esr/esrlen to consume events. */
unsigned transport_update_event(openvpn_transport_socket_t vsocket,
                        struct event_set_return *esr, int *esrlen);

void transport_request_events(openvpn_transport_socket_t indirect,
                              struct event_set *es, unsigned rwflags);

/* NOTE: transport_write and transport_read implicitly downcast from a
 * ssize_t to an int on return. Various link_socket_* functions
 * already do this, under the assumption that the return values will
 * always fit in an int, because the requested lengths always fit in
 * an int, otherwise the buffer structure would already be corrupted.
 */

static inline int
transport_write(openvpn_transport_socket_t indirect,
                struct buffer *buf, struct sockaddr *addr, socklen_t addrlen)
{
    return indirect->vtab->sendto(indirect, BPTR(buf), BLEN(buf), addr,
                                  addrlen);
}

static inline int
transport_read(openvpn_transport_socket_t indirect,
               struct buffer *buf, struct sockaddr *addr, socklen_t *addrlen)
{
    return indirect->vtab->recvfrom(indirect, BPTR(buf),
                                    buf_forward_capacity(buf), addr, addrlen);
}

#endif /* ENABLE_PLUGIN */

#endif /* !OPENVPN_TRANSPORT_H */
