#include "iris.h"
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sodium.h"

#define RANDOM_NUMBER_BUFFER_SIZE 4096

struct iris_socket_posix
{
    struct openvpn_vsocket_handle handle;
    struct iris_context *ctx;
    int fd;
    unsigned last_rwflags;
    unsigned char *seed;
    unsigned char *random_number_buffer;
    unsigned int random_number_buffer_offset;
};

static void
free_socket(struct iris_socket_posix *sock)
{
    if (!sock)
        return;
    
    if (sock->fd != -1)
        close(sock->fd);
    
    free(sock->seed);
    free(sock->random_number_buffer);
    free(sock);
}

static void
iris_posix_create_random_number(struct iris_socket_posix *sock)
{
    unsigned char *temp_random_number_buffer;
    sock->random_number_buffer_offset = 0;

    // Everytime the random number is generated instead of putting it in the buffer directly put it in a temp buffer that is 2x the size needed.
    temp_random_number_buffer = calloc(1, RANDOM_NUMBER_BUFFER_SIZE * 2);
    randombytes_buf_deterministic(temp_random_number_buffer, RANDOM_NUMBER_BUFFER_SIZE * 2, sock->seed);
    
    // Copy (memcpy) the first half into the seed and the second half into the random number buffer
    memcpy(sock->seed, temp_random_number_buffer, RANDOM_NUMBER_BUFFER_SIZE);
    memcpy(sock->random_number_buffer, &temp_random_number_buffer[RANDOM_NUMBER_BUFFER_SIZE], RANDOM_NUMBER_BUFFER_SIZE);
    
    free(temp_random_number_buffer);
}

static openvpn_vsocket_handle_t
iris_posix_bind(void *plugin_handle,
                     const struct sockaddr *addr, socklen_t len)
{
    struct iris_context *context = (struct iris_context *)plugin_handle;
    struct iris_socket_posix *sock = NULL;
    const char *password = context->password;
    const unsigned char *salt = (const unsigned char *)context->salt;
    
    sock = calloc(1, sizeof(struct iris_socket_posix));
    
    if (!sock)
    {
        goto error;
    }
    
    // Create and assign seed to sock->seed
    //FIXME: Needs salt
    sock->seed = calloc(1, randombytes_SEEDBYTES);
    sock->random_number_buffer = calloc(1, RANDOM_NUMBER_BUFFER_SIZE);
    
    int pwhash_result = crypto_pwhash(sock->seed,
                                      randombytes_SEEDBYTES,
                                      password,
                                      strlen(password),
                                      salt,
                                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                      crypto_pwhash_ALG_DEFAULT);
    if (pwhash_result != 0)
    {
        /* out of memory */
        goto error;
    }
    
    // Creates random numbers and assigns to the random_number_buffer and seed
    iris_posix_create_random_number(sock);
    
    sock->handle.vtab = &iris_socket_vtab;
    sock->ctx = (struct iris_context *) plugin_handle;
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
iris_posix_request_event(openvpn_vsocket_handle_t handle,
                              openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    iris_log(((struct iris_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "request-event: %d", rwflags);
    ((struct iris_socket_posix *) handle)->last_rwflags = 0;
    
    if (rwflags)
        event_set->vtab->set_event(event_set, ((struct iris_socket_posix *) handle)->fd, rwflags, handle);
}

// Tell us whether the underlying file descriptor is ready for R/W
static bool
iris_posix_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    iris_log(((struct iris_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "update-event: %p, %p, %d", handle, arg, rwflags);
    
    if (arg != handle)
        return false;
    
    ((struct iris_socket_posix *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned
iris_posix_pump(openvpn_vsocket_handle_t handle)
{
    iris_log(((struct iris_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "pump -> %d", ((struct iris_socket_posix *) handle)->last_rwflags);
    
    return ((struct iris_socket_posix *) handle)->last_rwflags;
}

//Decrypt/Encrypt
static void
iris_posix_transform_data(openvpn_vsocket_handle_t handle, void *buf, ssize_t number_of_bytes_read)
{
    struct iris_socket_posix *posix_sock = (struct iris_socket_posix *) handle;
    char *buffer = (char *)buf;
    
    // For each byte in buf XOR with offset number in random_number_buffer
    for (int counter = 0; counter < number_of_bytes_read; counter++)
    {
        buffer[counter] = posix_sock->random_number_buffer[posix_sock->random_number_buffer_offset] ^ buffer[counter];
        
        // Increase the offset by one
        posix_sock->random_number_buffer_offset++;
        
        // Check that the offset isn't beyond the scope of the random number
        if (posix_sock->random_number_buffer_offset >= RANDOM_NUMBER_BUFFER_SIZE)
        {
            // Generate a new random number if the last was used up
            iris_posix_create_random_number(posix_sock);
        }
    }
}

// Receive Data from the other side
static ssize_t
iris_posix_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len,
                         struct sockaddr *addr, socklen_t *addrlen)
{
    struct iris_socket_posix *posix_sock = (struct iris_socket_posix *) handle;
    
    // Our Socket
    int fd = posix_sock->fd;
    ssize_t number_of_bytes_read;

    // number_of_bytes_read returns the number of bytes that were read
    // If there were no bytes available on the network it returns 0
    // If there was an error -1 and sets the errno error
    number_of_bytes_read = recvfrom(fd, buf, len, 0, addr, addrlen);
    
    // If we receive "there is no data available right now, try again later"
    // Set a flag saying we are not ready to try again
    if (number_of_bytes_read < 0 && errno == EAGAIN)
    {
        ((struct iris_socket_posix *) handle)->last_rwflags &= ~OPENVPN_VSOCKET_EVENT_READ;
    }

    iris_log(posix_sock->ctx,
                  PLOG_DEBUG, "recvfrom(%d) -> %d", (int)len, (int)number_of_bytes_read);
    
    // Decrypts data previously encrypted
    iris_posix_transform_data(handle, buf, number_of_bytes_read);
    
    return number_of_bytes_read;
}

// Send data to the other side
static ssize_t
iris_posix_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len,
                       const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = ((struct iris_socket_posix *) handle)->fd;
    
    // On success, sendto() returns the number of characters sent.
    // On error, -1 is returned, and errno is set appropriately.
    ssize_t number_of_characters_sent;
    number_of_characters_sent = sendto(fd, buf, len, 0, addr, addrlen);
    
    if (number_of_characters_sent < 0 && errno == EAGAIN)
    {
        ((struct iris_socket_posix *) handle)->last_rwflags &= ~OPENVPN_VSOCKET_EVENT_WRITE;
    }
    
    //FIXME: not clear what to do here for partial transfers.
    if (number_of_characters_sent > len)
        number_of_characters_sent = len;
    
    iris_log(((struct iris_socket_posix *) handle)->ctx,
                  PLOG_DEBUG, "sendto(%d) -> %d", (int)len, (int)number_of_characters_sent);
    
    //Encrypts Data
    iris_posix_transform_data(handle, buf, number_of_characters_sent);

    return number_of_characters_sent;

error:
    return -1;
}

static void
iris_posix_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct iris_socket_posix *) handle);
}

// All of the functions that should be called by OpenVPN when an event happens
void
iris_initialize_socket_vtab(void)
{
    iris_socket_vtab.bind = iris_posix_bind;
    iris_socket_vtab.request_event = iris_posix_request_event;
    iris_socket_vtab.update_event = iris_posix_update_event;
    iris_socket_vtab.pump = iris_posix_pump;
    iris_socket_vtab.recvfrom = iris_posix_recvfrom;
    iris_socket_vtab.sendto = iris_posix_sendto;
    iris_socket_vtab.close = iris_posix_close;
}
