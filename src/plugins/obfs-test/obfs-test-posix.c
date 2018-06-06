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
    struct obfs_test_context *ctx;
    int fd;
    unsigned last_rwflags;
};

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
obfs_test_posix_bind(void *plugin_handle,
                     const struct sockaddr *addr, socklen_t len)
{
    struct obfs_test_socket_posix *sock = NULL;

    sock = calloc(1, sizeof(struct obfs_test_socket_posix));
    if (!sock)
        goto error;
    
    sock->handle.vtab = &obfs_test_socket_vtab;
    sock->ctx = (struct obfs_test_context *) plugin_handle;
    /* Note that sock->fd isn't -1 yet. Set it explicitly if there are ever any
       error exits before the socket() call. */

    // Actual creation of the real socket on the network
    sock->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock->fd == -1)
        goto error;
    
    if (fcntl(sock->fd, F_SETFL, fcntl(sock->fd, F_GETFL) | O_NONBLOCK))
        goto error;

    // Attach the socket to the address
    if (bind(sock->fd, addr, len))
        goto error;
    
    return &sock->handle;

error:
    free_socket(sock);
    return NULL;
}

// What OpenVPN is requesting to be notified of
static void
obfs_test_posix_request_event(openvpn_vsocket_handle_t handle,
                              openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "request-event: %d", rwflags);
    ((struct obfs_test_socket_posix *) handle)->last_rwflags = 0;
    
    if (rwflags)
        event_set->vtab->set_event(event_set, ((struct obfs_test_socket_posix *) handle)->fd, rwflags, handle);
}

// Tell us whether the underlying file descriptor is ready for R/W
static bool
obfs_test_posix_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "update-event: %p, %p, %d", handle, arg, rwflags);
    
    if (arg != handle)
        return false;
    
    ((struct obfs_test_socket_posix *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned
obfs_test_posix_pump(openvpn_vsocket_handle_t handle)
{
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "pump -> %d", ((struct obfs_test_socket_posix *) handle)->last_rwflags);
    
    return ((struct obfs_test_socket_posix *) handle)->last_rwflags;
}

// Receive Data from the other side
static ssize_t
obfs_test_posix_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len,
                         struct sockaddr *addr, socklen_t *addrlen)
{
    // Our Socket
    int fd = ((struct obfs_test_socket_posix *) handle)->fd;
    ssize_t number_of_bytes_read;

    // number_of_bytes_read returns the number of bytes that were read
    // If there were no bytes available on the network it returns 0
    // If there was an error -1 and sets the errno error
    number_of_bytes_read = recvfrom(fd, buf, len, 0, addr, addrlen);
    
    // If we receive "there is no data available right now, try again later"
    // Set a flag saying we are not ready to try again
    if (number_of_bytes_read < 0 && errno == EAGAIN)
    {
        ((struct obfs_test_socket_posix *) handle)->last_rwflags &= ~OPENVPN_VSOCKET_EVENT_READ;
    }

    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "recvfrom(%d) -> %d", (int)len, (int)number_of_bytes_read);
    
    return number_of_bytes_read;
}

// Send data to the other side
static ssize_t
obfs_test_posix_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len,
                       const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = ((struct obfs_test_socket_posix *) handle)->fd;
    
    // On success, sendto() returns the number of characters sent.
    // On error, -1 is returned, and errno is set appropriately.
    ssize_t number_of_characters_sent;
    number_of_characters_sent = sendto(fd, buf, len, 0, addr, addrlen);
    
    if (number_of_characters_sent < 0 && errno == EAGAIN)
    {
        ((struct obfs_test_socket_posix *) handle)->last_rwflags &= ~OPENVPN_VSOCKET_EVENT_WRITE;
    }
    
    //FIXME: not clear what to do here for partial transfers.
    if (number_of_characters_sent > len)
        number_of_characters_sent = len;
    
    obfs_test_log(((struct obfs_test_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "sendto(%d) -> %d", (int)len, (int)number_of_characters_sent);

    return number_of_characters_sent;

error:
    return -1;
}

static void
obfs_test_posix_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct obfs_test_socket_posix *) handle);
}

// All of the functions that should be called by OpenVPN when an event happens
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
