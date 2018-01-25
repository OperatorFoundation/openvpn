#ifndef OPENVPN_VSOCKET_H_
#define OPENVPN_VSOCKET_H_

/* PLATFORM: only POSIX-y platforms or Win32 here */

#ifdef _WIN32

/* Win32 */
#define OPENVPN_VSOCKET_PLATFORM_WIN32
#include <stdbool.h>
#include <windows.h>
#include <winsock2.h>

typedef const struct {
    HANDLE read;
    HANDLE write;
} *openvpn_vsocket_native_event_t;

typedef int openvpn_vsocket_socklen_t;

#else

/* POSIX-y */
#define OPENVPN_VSOCKET_PLATFORM_POSIX
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef int openvpn_vsocket_native_event_t;
typedef socklen_t openvpn_vsocket_socklen_t;

#endif

#define OPENVPN_VSOCKET_EVENT_READ  (1<<0)
#define OPENVPN_VSOCKET_EVENT_WRITE (1<<1)

typedef struct openvpn_vsocket_event_set_handle *openvpn_vsocket_event_set_handle_t;

struct openvpn_vsocket_event_set_vtab {
    void (*set_event)(openvpn_vsocket_event_set_handle_t handle,
                      openvpn_vsocket_native_event_t ev, unsigned rwflags, void *arg);
};

/* Handle to a set of physical I/O events to wait for. Implementation
   extends this structure with state. */
struct openvpn_vsocket_event_set_handle {
    const struct openvpn_vsocket_event_set_vtab *vtab;
};

typedef struct openvpn_vsocket_handle *openvpn_vsocket_handle_t;

/* Handle to a virtual datagram socket, non-connection-oriented. Implementation
   extends this structure with state. */
struct openvpn_vsocket_handle {
    const struct openvpn_vsocket_vtab *vtab;
};

/* Sequence is:
     - bind : addr -> handle
       + addr/len may be NULL/0 for "auto/deferred, will initiate"
     - request_event : desired virtual rwflags (physical rwflags set via event set callbacks)
     - (I/O wait)
     - update_event : physical rwflags
       + returns true if recognized
     - pump : returns active virtual rwflags
     - recvfrom/sendto should normally only be called after pump returns corresponding rwflags
 */

/* TODO: document or coalesce error behavior between platforms (currently uses platform-native errors only) */

struct openvpn_vsocket_vtab {
    openvpn_vsocket_handle_t (*bind)(const struct sockaddr *addr, openvpn_vsocket_socklen_t len);
    void (*request_event)(openvpn_vsocket_handle_t handle,
                           openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags);
    bool (*update_event)(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags);
    unsigned (*pump)(openvpn_vsocket_handle_t handle);
    ssize_t (*recvfrom)(openvpn_vsocket_handle_t handle, void *buf, size_t len,
                        struct sockaddr *addr, openvpn_vsocket_socklen_t *addrlen);
    ssize_t (*sendto)(openvpn_vsocket_handle_t handle, const void *buf, size_t len,
                      const struct sockaddr *addr, openvpn_vsocket_socklen_t addrlen);
    void (*close)(openvpn_vsocket_handle_t handle);
};

#endif
