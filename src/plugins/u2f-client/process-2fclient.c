#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <curl/curl.h>
#include <u2f-host/u2f-host.h>

#include "openvpn-plugin.h"
#include "comm-2fclient.h"

static const char program_name[] = "openvpn-2fclient";

static int
do_auth_request(const char *packet, size_t len, struct msghdr *msg,
                const char **error)
{
    int fd;
    const char *username;
    const char *password;

    if (comm_2fclient_parse_packet(packet, len, msg,
                                   "Fss", &fd, &username, &password))
    {
        *error = "malformed auth request";
        return AUTH_RESPONSE_ERROR;
    }

    /* The worst password check ever, redux. */
    int ok = (strcmp(username, password) == 0);
    return ok ? AUTH_RESPONSE_IMMEDIATE_PERMIT : AUTH_RESPONSE_IMMEDIATE_DENY;
}

static void
control_loop(int sock)
{
    for (;;)
    {
        ssize_t len;
        union {
            char data[CMSG_SPACE(sizeof(int) * MAX_PACKET_FDS)];
            struct cmsghdr align;
        } ancillary;
        char packet[MAX_PACKET_BYTES];
        struct iovec iov = {
            .iov_base = packet,
            .iov_len = MAX_PACKET_BYTES
        };
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = ancillary.data,
            .msg_controllen = sizeof(ancillary.data)
        };

        do {
            len = recvmsg(sock, &msg, 0);
        } while (len < 0 && errno == EAGAIN);

        if (len == 0)
        {
            comm_2fclient_send_error(sock, "bad zero-length packet");
            continue;
        }

        int result;
        const char *error;

        switch ((unsigned char)packet[0])
        {
            case OP_TERMINATE:
                comm_2fclient_send_packet(sock, OP_TERMINATE_ACK, "");
                /* return rather than break, to exit loop. */
                return;
            case OP_AUTH_REQUEST:
                result = do_auth_request(packet, (size_t)len, &msg, &error);
                switch (result)
                {
                    case AUTH_RESPONSE_IMMEDIATE_PERMIT:
                        comm_2fclient_send_packet(sock, OP_AUTH_RESPONSE, "b",
                                                  OPENVPN_PLUGIN_FUNC_SUCCESS);
                        break;
                    case AUTH_RESPONSE_PENDING:
                        comm_2fclient_send_packet(sock, OP_AUTH_RESPONSE, "b",
                                                  OPENVPN_PLUGIN_FUNC_DEFERRED);
                        break;
                    case AUTH_RESPONSE_IMMEDIATE_DENY:
                        comm_2fclient_send_packet(sock, OP_AUTH_RESPONSE, "b",
                                                  OPENVPN_PLUGIN_FUNC_ERROR);
                        break;
                    case AUTH_RESPONSE_ERROR:
                        comm_2fclient_send_error(sock, error);
                        break;
                    default:
                        abort();
                }
                break;
            default:
                comm_2fclient_send_error(sock, "unrecognized opcode");
                break;
        }

        /* TODO (defensive): close_spare_fds(&msg); */
    }
}

static int
parse_fd(const char *arg)
{
    errno = 0;
    unsigned long n = strtoul(arg, NULL, 10);
    if (errno)
        return -1;
#if ULONG_MAX > INT_MAX
    if (n > (unsigned long)INT_MAX)
        return -1;
#endif
    return (int)n;
}

static void
show_usage(void)
{
    fprintf(stderr, "Usage: %s -sSOCKET_FD\n", program_name);
    fputs("This program is normally only called by its attendant plugin.\n",
          stderr);
}

int
main(int argc, char *argv[])
{
    int control_socket = -1;
    int option;

    while ((option = getopt(argc, argv, ":s:h")) != -1)
    {
        switch (option)
        {
            case 's':
                control_socket = parse_fd(optarg);
                break;
            case 'h':
                show_usage();
                exit(0);
            case ':':
                fprintf(stderr, "%s: option -%c requires an argument\n",
                        program_name, optopt);
                show_usage();
                exit(64);
            case '?':
                fprintf(stderr, "%s: unrecognized option -%c\n",
                        program_name, optopt);
                show_usage();
                exit(64);
            default:
                fprintf(stderr, "%s: error processing options\n",
                        program_name);
                show_usage();
                exit(64);
        }
    }

    if (control_socket == -1)
    {
        fprintf(stderr, "%s: no control socket found\n", program_name);
        show_usage();
        exit(66);
    }

    comm_2fclient_send_packet(control_socket, OP_INITIALIZED,
                              "b", BACKEND_PROTOCOL_VERSION);
    control_loop(control_socket);
    return 0;
}
