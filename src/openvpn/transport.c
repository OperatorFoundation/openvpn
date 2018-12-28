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


#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_PLUGIN

#include "error.h"
#include "event.h"
#include "plugin.h"
#include "socket.h"
#include "transport.h"
#include "openvpn-transport.h"

bool
transport_prepare(const struct plugin_list *plugins,
                  const char **transport_plugin_argv,
                  struct openvpn_transport_bind_vtab1 **vtabp,
                  openvpn_plugin_handle_t *handlep,
                  openvpn_transport_args_t *argsp)
{
    const char *expected_so_pathname = transport_plugin_argv[0];
    int argc = 0;

    while (transport_plugin_argv[argc])
    {
        argc++;
    }

    for (int i = 0; i < plugins->common->n; i++)
    {
        struct plugin *p = &plugins->common->plugins[i];
        if (p->so_pathname && !strcmp(p->so_pathname, expected_so_pathname))
        {
            /* Pathname matches; this is the plugin requested. */
            if (!(p->plugin_type_mask
                  & OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TRANSPORT)))
            {
                msg(M_FATAL,
                    "INDIRECT: plugin %s does not indicate TRANSPORT functionality",
                    p->so_pathname);
            }

            size_t size;
            struct openvpn_transport_bind_vtab1 *vtab = NULL;
            if (p->get_vtab)
            {
                vtab = p->get_vtab(OPENVPN_VTAB_TRANSPORT_BIND_V1, &size);
            }

            if (!vtab)
            {
                msg(M_FATAL,
                    "INDIRECT: plugin %s has no TRANSPORT_BIND_V1 table",
                    p->so_pathname);
            }

            /* Sanity checks on the vtable. */
            if (!(size == sizeof(*vtab) && vtab->bind
                  && ((vtab->parseargs && vtab->argerror && vtab->freeargs)
                      || (!vtab->parseargs && !vtab->argerror
                          && !vtab->freeargs))))
            {
                msg(M_FATAL,
                    "INDIRECT: plugin %s returned a faulty TRANSPORT_BIND_V1 table",
                    p->so_pathname);
            }

            openvpn_transport_args_t args = NULL;
            if (vtab->parseargs)
            {
                args = vtab->parseargs(p->plugin_handle, transport_plugin_argv,
                                       argc);

                const char *argerror = vtab->argerror(args);
                if (argerror)
                {
                    msg(M_FATAL,
                        "INDIRECT: invalid arguments to transport-plugin %s: %s",
                        p->so_pathname, argerror);
                }
            }

            *vtabp = vtab;
            *handlep = p->plugin_handle;
            *argsp = args;

            return true;
        }
    }

    return false;
}

openvpn_transport_socket_t
transport_bind(const struct plugin_list *plugins,
               const char **transport_plugin_argv, sa_family_t ai_family,
               struct addrinfo *bind_addresses)
{
    openvpn_plugin_handle_t handle;
    openvpn_transport_args_t args;
    openvpn_transport_socket_t indirect;
    struct openvpn_transport_bind_vtab1 *vtab;
    struct addrinfo *cur = NULL;
    struct openvpn_sockaddr zero;

    if (!transport_prepare(plugins, transport_plugin_argv, &vtab, &handle,
                           &args))
    {
        msg(M_FATAL, "INDIRECT: Socket bind failed: provider plugin not found");
    }

    /* Partially replicates the functionality of socket_bind. No bind_ipv6_only
     * or other such options, presently.
     */
    if (bind_addresses)
    {
        for (cur = bind_addresses; cur; cur = cur->ai_next)
        {
            if (cur->ai_family == ai_family)
            {
                break;
            }
        }

        if (!cur)
        {
            msg(M_FATAL, "INDIRECT: Socket bind failed: Addr to bind has no %s record",
                addr_family_name(ai_family));
        }
    }

    if (cur)
    {
        indirect = vtab->bind(handle, args, cur->ai_addr, cur->ai_addrlen);
    }
    else if (ai_family == AF_UNSPEC)
    {
        msg(M_ERR, "INDIRECT: cannot bind with unspecified address family");
    }
    else
    {
        memset(&zero, 0, sizeof(zero));
        zero.addr.sa.sa_family = ai_family;
        addr_zero_host(&zero);
        indirect = vtab->bind(handle, args, &zero.addr.sa, af_addr_size(ai_family));
    }

    if (!indirect)
    {
        msg(M_ERR, "INDIRECT: Socket bind failed");
    }

    if (vtab->freeargs)
    {
        vtab->freeargs(args);
    }

    return indirect;
}

struct encapsulated_event_set
{
    struct openvpn_transport_event_set_handle handle;
    struct event_set *real;
};

#if EVENT_READ == OPENVPN_TRANSPORT_EVENT_READ \
    && EVENT_WRITE == OPENVPN_TRANSPORT_EVENT_WRITE
#define TRANSPORT_EVENT_BITS_IDENTICAL 1
#else
#define TRANSPORT_EVENT_BITS_IDENTICAL 0
#endif

static inline unsigned
translate_rwflags_in(unsigned vrwflags)
{
#if TRANSPORT_EVENT_BITS_IDENTICAL
    return vrwflags;
#else
    unsigned rwflags = 0;
    if (vrwflags & OPENVPN_TRANSPORT_EVENT_READ)
    {
        rwflags |= EVENT_READ;
    }
    if (vrwflags & OPENVPN_TRANSPORT_EVENT_WRITE)
    {
        rwflags |= EVENT_WRITE;
    }
    return rwflags;
#endif
}

static inline unsigned
translate_rwflags_out(unsigned rwflags)
{
#if TRANSPORT_EVENT_BITS_IDENTICAL
    return rwflags;
#else
    unsigned vrwflags = 0;
    if (rwflags & EVENT_READ)
    {
        vrwflags |= OPENVPN_TRANSPORT_EVENT_READ;
    }
    if (rwflags & EVENT_WRITE)
    {
        vrwflags |= OPENVPN_TRANSPORT_EVENT_WRITE;
    }
    return vrwflags;
#endif
}

static void
encapsulated_event_set_set_event(openvpn_transport_event_set_handle_t handle,
                                 openvpn_transport_native_event_t vev,
                                 unsigned vrwflags, void *arg)
{
    unsigned rwflags = translate_rwflags_in(vrwflags);
    event_t ev;
#ifdef _WIN32
    struct rw_handle rw;
    rw.read = vev->read;
    rw.write = vev->write;
    ev = &rw;
#else
    ev = vev;
#endif

    struct event_set *es = ((struct encapsulated_event_set *) handle)->real;
    /* If rwflags == 0, we do nothing, because this is always one-shot mode. */
    if (rwflags != 0)
    {
        event_ctl(es, ev, rwflags, arg);
    }
}

static const struct openvpn_transport_event_set_vtab encapsulated_event_set_vtab = {
    encapsulated_event_set_set_event
};

unsigned
transport_pump(openvpn_transport_socket_t indirect,
               struct event_set_return *esr, int *esrlen)
{
    int i = 0;
    while (i < *esrlen)
    {
        unsigned vrwflags = translate_rwflags_out(esr[i].rwflags);
        if (indirect->vtab->update_event(indirect, esr[i].arg, vrwflags))
        {
            /* Consume the event; move the last one in place of it. */
            if (i != *esrlen - 1)
            {
                memcpy(&esr[i], &esr[*esrlen-1], sizeof(*esr));
            }
            (*esrlen)--;
        }
        else
        {
            /* Don't consume the event; move to the next one. */
            i++;
        }
    }

    return translate_rwflags_in(indirect->vtab->pump(indirect));
}

void
transport_request_events(openvpn_transport_socket_t indirect,
                         struct event_set *es, unsigned rwflags)
{
    unsigned vrwflags = translate_rwflags_out(rwflags);
    struct encapsulated_event_set encapsulated_es;
    encapsulated_es.handle.vtab = &encapsulated_event_set_vtab;
    encapsulated_es.real = es;
    indirect->vtab->request_event(indirect, &encapsulated_es.handle, vrwflags);
}

#endif  /* ENABLE_PLUGIN */
