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
    struct openvpn_vsocket_handle handle;
    int fd;
    unsigned last_rwflags;
};

struct openvpn_vsocket_vtab obfs_test_socket_vtab;

static void
free_socket(struct obfs_test_socket_posix *sock)
{
    if (!sock)
        return;
    if (sock->fd != -1)
        close(sock->fd);
    free(sock);
}

static openvpn_vsocket_handle_t
obfs_test_posix_bind(void *handle,
                     const struct sockaddr *addr, socklen_t len)
{
    struct obfs_test_socket_posix *sock = NULL;
    struct sockaddr *addr_rev = NULL;

    addr_rev = calloc(1, len);
    if (!addr_rev)
        goto error;
    memcpy(addr_rev, addr, len);
    obfs_test_munge_addr(addr_rev, len);

    sock = calloc(1, sizeof(struct obfs_test_socket_posix));
    if (!sock)
        goto error;
    sock->handle.vtab = &obfs_test_socket_vtab;
    /* Note that sock->fd isn't -1 yet. Set it explicitly if there are ever any
       error exits before the socket() call. */

    /* FIXME: should take family from bind address */
    sock->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd == -1)
        goto error;
    if (fcntl(sock->fd, F_SETFL, fcntl(sock->fd, F_GETFL) | O_NONBLOCK))
        goto error;

    if (bind(sock->fd, addr_rev, len))
        goto error;
    free(addr_rev);
    return &sock->handle;

error:
    free_socket(sock);
    free(addr_rev);
    return NULL;
}

static void
obfs_test_posix_request_event(openvpn_vsocket_handle_t handle,
                              openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    /* FIXME: this assumes one-shot events. The fast-mode/non-fast-mode distinction in
       the core event loop is awkward here. */
    warnx("obfs-test: request-event: %d", rwflags);
    ((struct obfs_test_socket_posix *) handle)->last_rwflags = 0;
    if (rwflags)
        event_set->vtab->set_event(event_set, ((struct obfs_test_socket_posix *) handle)->fd,
                                   rwflags, handle);
}

static bool
obfs_test_posix_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    warnx("obfs-test: update-event: %p, %p, %d", handle, arg, rwflags);
    if (arg != handle)
        return false;
    /* TODO(low): do we need to handle what happens if core starts splitting up events here? */
    ((struct obfs_test_socket_posix *) handle)->last_rwflags = rwflags;
    return true;
}

static unsigned
obfs_test_posix_pump(openvpn_vsocket_handle_t handle)
{
    warnx("obfs-test: pump -> %d", ((struct obfs_test_socket_posix *) handle)->last_rwflags);
    return ((struct obfs_test_socket_posix *) handle)->last_rwflags;
}

static ssize_t
obfs_test_posix_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len,
                         struct sockaddr *addr, socklen_t *addrlen)
{
    int fd = ((struct obfs_test_socket_posix *) handle)->fd;
    ssize_t result = recvfrom(fd, buf, len, 0, addr, addrlen);
    if (result < 0 && errno == EAGAIN)
        ((struct obfs_test_socket_posix *) handle)->last_rwflags &= ~OPENVPN_VSOCKET_EVENT_READ;
    if (*addrlen > 0)
        obfs_test_munge_addr(addr, *addrlen);
    if (result > 0)
        result = obfs_test_unmunge_buf(buf, result);
    warnx("obfs-test: recvfrom(%d) -> %d", (int)len, (int)result);
    return result;
}

static ssize_t
obfs_test_posix_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len,
                       const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = ((struct obfs_test_socket_posix *) handle)->fd;
    struct sockaddr *addr_rev = calloc(1, addrlen);
    void *buf_munged = malloc(obfs_test_max_munged_buf_size(len));
    size_t len_munged;
    ssize_t result;
    if (!addr_rev || !buf_munged)
        goto error;

    memcpy(addr_rev, addr, addrlen);
    obfs_test_munge_addr(addr_rev, addrlen);
    len_munged = obfs_test_munge_buf(buf_munged, buf, len);
    result = sendto(fd, buf_munged, len_munged, 0, addr_rev, addrlen);
    if (result < 0 && errno == EAGAIN)
        ((struct obfs_test_socket_posix *) handle)->last_rwflags &= ~OPENVPN_VSOCKET_EVENT_WRITE;
    /* FIXME: Doesn't handle partial transfers. (That might not be an
       issue here anyway?) This is just here to preserve the expected
       invariant of return value <= len. (What we really need is to
       either punt on partial sends entirely (or almost-entirely) or
       decide to translate effective lengths back. Almost definitely
       the former. */
    if (result > len)
        result = len;
    warnx("obfs-test: sendto(%d) -> %d", (int)len, (int)result);
    free(addr_rev);
    free(buf_munged);
    return result;

error:
    free(addr_rev);
    free(buf_munged);
    return -1;
}

static void
obfs_test_posix_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct obfs_test_socket_posix *) handle);
}

void
obfs_test_initialize_socket_vtab(void)
{
    obfs_test_socket_vtab.bind = obfs_test_posix_bind;
    obfs_test_socket_vtab.request_event = obfs_test_posix_request_event;
    obfs_test_socket_vtab.update_event = obfs_test_posix_update_event;
    obfs_test_socket_vtab.pump = obfs_test_posix_pump;
    obfs_test_socket_vtab.recvfrom = obfs_test_posix_recvfrom;
    obfs_test_socket_vtab.sendto = obfs_test_posix_sendto;
    obfs_test_socket_vtab.close = obfs_test_posix_close;
}
