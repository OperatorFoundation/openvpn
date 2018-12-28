#include "obfs-test.h"
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct obfs_test_socket_posix
{
    struct openvpn_transport_socket handle;
    struct obfs_test_args args;
    struct obfs_test_context *ctx;
    int fd;
    unsigned last_rwflags;
};

static void
free_socket(struct obfs_test_socket_posix *sock)
{
    if (!sock)
    {
        return;
    }
    if (sock->fd != -1)
    {
        close(sock->fd);
    }
    free(sock);
}

static openvpn_transport_socket_t
obfs_test_posix_bind(void *plugin_handle, openvpn_transport_args_t args,
                     const struct sockaddr *addr, socklen_t len)
{
    struct obfs_test_socket_posix *sock = NULL;
    struct sockaddr *addr_rev = NULL;

    addr_rev = calloc(1, len);
    if (!addr_rev)
    {
        goto error;
    }
    memcpy(addr_rev, addr, len);
    obfs_test_munge_addr(addr_rev, len);

    sock = calloc(1, sizeof(struct obfs_test_socket_posix));
    if (!sock)
    {
        goto error;
    }
    sock->handle.vtab = &obfs_test_socket_vtab;
    sock->ctx = (struct obfs_test_context *) plugin_handle;
    memcpy(&sock->args, args, sizeof(sock->args));
    /* Note that sock->fd isn't -1 yet. Set it explicitly if there are ever any
     * error exits before the socket() call. */

    sock->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd == -1)
    {
        goto error;
    }
    if (fcntl(sock->fd, F_SETFL, fcntl(sock->fd, F_GETFL) | O_NONBLOCK))
    {
        goto error;
    }

    if (bind(sock->fd, addr_rev, len))
    {
        goto error;
    }
    free(addr_rev);
    return &sock->handle;

error:
    free_socket(sock);
    free(addr_rev);
    return NULL;
}

static void
obfs_test_posix_request_event(openvpn_transport_socket_t handle,
                              openvpn_transport_event_set_handle_t event_set, unsigned rwflags)
{
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "request-event: %d", rwflags);
    ((struct obfs_test_socket_posix *) handle)->last_rwflags = 0;
    if (rwflags)
    {
        event_set->vtab->set_event(event_set, ((struct obfs_test_socket_posix *) handle)->fd,
                                   rwflags, handle);
    }
}

static bool
obfs_test_posix_update_event(openvpn_transport_socket_t handle, void *arg, unsigned rwflags)
{
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "update-event: %p, %p, %d", handle, arg, rwflags);
    if (arg != handle)
    {
        return false;
    }
    ((struct obfs_test_socket_posix *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned
obfs_test_posix_pump(openvpn_transport_socket_t handle)
{
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "pump -> %d", ((struct obfs_test_socket_posix *) handle)->last_rwflags);
    return ((struct obfs_test_socket_posix *) handle)->last_rwflags;
}

static ssize_t
obfs_test_posix_recvfrom(openvpn_transport_socket_t handle, void *buf, size_t len,
                         struct sockaddr *addr, socklen_t *addrlen)
{
    int fd = ((struct obfs_test_socket_posix *) handle)->fd;
    ssize_t result;

again:
    result = recvfrom(fd, buf, len, 0, addr, addrlen);
    if (result < 0 && errno == EAGAIN)
    {
        ((struct obfs_test_socket_posix *) handle)->last_rwflags &= ~OPENVPN_TRANSPORT_EVENT_READ;
    }
    if (*addrlen > 0)
    {
        obfs_test_munge_addr(addr, *addrlen);
    }
    if (result > 0)
    {
        struct obfs_test_args *how = &((struct obfs_test_socket_posix *) handle)->args;
        result = obfs_test_unmunge_buf(how, buf, result);
        if (result < 0)
        {
            /* Pretend that read never happened. */
            goto again;
        }
    }

    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "recvfrom(%d) -> %d", (int)len, (int)result);
    return result;
}

static ssize_t
obfs_test_posix_sendto(openvpn_transport_socket_t handle, const void *buf, size_t len,
                       const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = ((struct obfs_test_socket_posix *) handle)->fd;
    struct sockaddr *addr_rev = calloc(1, addrlen);
    void *buf_munged = malloc(obfs_test_max_munged_buf_size(len));
    size_t len_munged;
    ssize_t result;
    if (!addr_rev || !buf_munged)
    {
        goto error;
    }

    memcpy(addr_rev, addr, addrlen);
    obfs_test_munge_addr(addr_rev, addrlen);
    struct obfs_test_args *how = &((struct obfs_test_socket_posix *) handle)->args;
    len_munged = obfs_test_munge_buf(how, buf_munged, buf, len);
    result = sendto(fd, buf_munged, len_munged, 0, addr_rev, addrlen);
    if (result < 0 && errno == EAGAIN)
    {
        ((struct obfs_test_socket_posix *) handle)->last_rwflags &= ~OPENVPN_TRANSPORT_EVENT_WRITE;
    }
    /* TODO: not clear what to do here for partial transfers. */
    if (result > len)
    {
        result = len;
    }
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "sendto(%d) -> %d", (int)len, (int)result);
    free(addr_rev);
    free(buf_munged);
    return result;

error:
    free(addr_rev);
    free(buf_munged);
    return -1;
}

static void
obfs_test_posix_close(openvpn_transport_socket_t handle)
{
    free_socket((struct obfs_test_socket_posix *) handle);
}

void
obfs_test_initialize_vtabs_platform(void)
{
    obfs_test_bind_vtab.bind = obfs_test_posix_bind;
    obfs_test_socket_vtab.request_event = obfs_test_posix_request_event;
    obfs_test_socket_vtab.update_event = obfs_test_posix_update_event;
    obfs_test_socket_vtab.pump = obfs_test_posix_pump;
    obfs_test_socket_vtab.recvfrom = obfs_test_posix_recvfrom;
    obfs_test_socket_vtab.sendto = obfs_test_posix_sendto;
    obfs_test_socket_vtab.close = obfs_test_posix_close;
}
