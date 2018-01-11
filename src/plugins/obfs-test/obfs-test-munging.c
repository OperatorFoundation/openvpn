#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include "obfs-test.h"
#ifdef OPENVPN_VSOCKET_PLATFORM_POSIX
#include <sys/socket.h>
#include <netinet/in.h>
typedef in_port_t obfs_test_in_port_t;
#else
#include <winsock2.h>
#include <ws2tcpip.h>
typedef u_short obfs_test_in_port_t;
#endif

static obfs_test_in_port_t
munge_port(obfs_test_in_port_t port)
{
    return port ^ 15;
}

/* Reversible. */
void
obfs_test_munge_addr(struct sockaddr *addr, openvpn_vsocket_socklen_t len)
{
    struct sockaddr_in *inet;
    struct sockaddr_in6 *inet6;

    switch (addr->sa_family)
    {
        case AF_INET:
            inet = (struct sockaddr_in *) addr;
            inet->sin_port = munge_port(inet->sin_port);
            break;

        case AF_INET6:
            inet6 = (struct sockaddr_in6 *) addr;
            inet6->sin6_port = munge_port(inet6->sin6_port);
            break;

        default:
            break;
    }
}

/* Six fixed bytes, six repeated bytes. It's only a silly transformation. */
#define MUNGE_OVERHEAD 12

size_t
obfs_test_max_munged_buf_size(size_t clear_size)
{
    return clear_size + MUNGE_OVERHEAD;
}

ssize_t
obfs_test_unmunge_buf(char *buf, size_t len)
{
    int i;

    if (len < 6)
        goto bad;
    for (i = 0; i < 6; i++)
    {
        if (buf[i] != i)
            goto bad;
    }

    for (i = 0; i < 6 && (6 + 2*i) < len; i++)
    {
        if (len < (6 + 2*i + 1) || buf[6 + 2*i] != buf[6 + 2*i + 1])
            goto bad;
        buf[i] = buf[6 + 2*i];
    }

    if (len > 18)
    {
        memmove(buf + 6, buf + 18, len - 18);
        len -= 12;
    }
    else
    {
        len -= 6;
        len /= 2;
    }

    return len;

bad:
    /* TODO: this really isn't the best way to report this error */
    errno = EIO;
    return -1;
}

/* out must have space for len+MUNGE_OVERHEAD bytes. out and in must
   not overlap. */
size_t
obfs_test_munge_buf(char *out, const char *in, size_t len)
{
    int i, n;
    size_t out_len = 6;

    for (i = 0; i < 6; i++)
        out[i] = i;
    n = len < 6 ? len : 6;
    for (i = 0; i < n; i++)
        out[6 + 2*i] = out[6 + 2*i + 1] = in[i];
    if (len > 6)
    {
        memmove(out + 18, in + 6, len - 6);
        out_len = len + 12;
    }
    else
    {
        out_len = 6 + 2*len;
    }

    return out_len;
}
